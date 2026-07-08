//! Session registry - manages all active client sessions.
//!
//! The registry:
//! - Creates new sessions on client connect
//! - Tracks active sessions by ID
//! - Provides session lookup
//! - Cleans up idle sessions
//! - Enforces max session limit
//!
//! Each session ID gets its own dedicated DuckDB connection, providing full
//! isolation between clients (separate catalogs, transactions, temp tables, etc.).

use std::collections::HashMap;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, instrument, warn};

use crate::config::ServerConfig;
use crate::engine::EngineFactory;
use crate::error::ServerError;
use crate::session::id::SessionId;
use crate::session::Session;

/// Registry for managing all active sessions
#[derive(Clone)]
pub struct SessionRegistry {
    inner: Arc<RwLock<RegistryInner>>,
    factory: Arc<EngineFactory>,
    max_sessions: usize,
    session_timeout: Duration,
    session_permits: Arc<Semaphore>,
}

#[derive(Clone, Serialize)]
pub struct SessionRegistrySnapshot {
    pub total_sessions: usize,
    pub max_sessions: usize,
    pub session_timeout_seconds: u64,
    pub oldest_idle_ms: u64,
    pub average_idle_ms: u64,
}

struct RegistryInner {
    sessions: HashMap<SessionId, SessionEntry>,
}

struct SessionEntry {
    session: Arc<Session>,
    _permit: OwnedSemaphorePermit,
}

impl SessionRegistry {
    /// Create a new session registry
    #[instrument(skip(config, factory))]
    pub fn new(config: &ServerConfig, factory: Arc<EngineFactory>) -> Result<Self, ServerError> {
        let max_sessions = config.max_sessions.unwrap_or(100);
        let session_timeout = Duration::from_secs(config.session_timeout_seconds.unwrap_or(1800)); // 30min default

        info!(
            max_sessions,
            session_timeout_seconds = session_timeout.as_secs(),
            "session registry initialized"
        );

        Ok(Self {
            inner: Arc::new(RwLock::new(RegistryInner {
                sessions: HashMap::new(),
            })),
            factory,
            max_sessions,
            session_timeout,
            session_permits: Arc::new(Semaphore::new(max_sessions)),
        })
    }

    pub fn engine_factory(&self) -> Arc<EngineFactory> {
        self.factory.clone()
    }

    pub fn snapshot(&self) -> SessionRegistrySnapshot {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let total_sessions = inner.sessions.len();
        let session_timeout_seconds = self.session_timeout.as_secs();
        let mut total_idle_ms = 0u64;
        let mut oldest_idle_ms = 0u64;

        for entry in inner.sessions.values() {
            let idle_ms = entry.session.idle_duration().as_millis() as u64;
            total_idle_ms = total_idle_ms.saturating_add(idle_ms);
            if idle_ms > oldest_idle_ms {
                oldest_idle_ms = idle_ms;
            }
        }

        let average_idle_ms = if total_sessions == 0 {
            0
        } else {
            total_idle_ms / total_sessions as u64
        };

        SessionRegistrySnapshot {
            total_sessions,
            max_sessions: self.max_sessions,
            session_timeout_seconds,
            oldest_idle_ms,
            average_idle_ms,
        }
    }

    /// Clean up idle sessions that have exceeded the timeout
    #[instrument(skip(self))]
    pub fn cleanup_idle_sessions(&self) -> usize {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = inner.sessions.len();

        inner.sessions.retain(|id, entry| {
            if entry.session.idle_duration() > self.session_timeout {
                info!(
                    session_id = %id,
                    idle_duration = ?entry.session.idle_duration(),
                    "removing idle session"
                );
                false
            } else {
                true
            }
        });

        let removed = before - inner.sessions.len();
        if removed > 0 {
            info!(
                removed,
                total_sessions = inner.sessions.len(),
                "cleaned up idle sessions"
            );
        }
        removed
    }

    /// Look up an existing session by ID without creating one (read lock only).
    ///
    /// Used by the duckvis auth gate to inspect a session's auth binding before
    /// deciding whether to create a new (workspace-scoped) session.
    pub fn get_by_id(&self, session_id: &SessionId) -> Option<Arc<Session>> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.sessions.get(session_id).map(|entry| entry.session.clone())
    }

    /// Get or create session by session ID.
    ///
    /// Each session ID gets its own dedicated DuckDB connection, providing
    /// full isolation between clients (separate catalogs, transactions,
    /// temp tables, etc.).
    pub async fn get_or_create_by_id(
        &self,
        session_id: &SessionId,
    ) -> Result<Arc<Session>, ServerError> {
        self.get_or_create_by_id_with_auth(session_id, None).await
    }

    /// Get or create a session by ID, binding the supplied duckvis auth on
    /// creation. An already-existing session keeps its original auth binding
    /// (the caller re-verifies the returned session's auth to close the create
    /// race).
    pub async fn get_or_create_by_id_with_auth(
        &self,
        session_id: &SessionId,
        auth: Option<crate::session::SessionAuth>,
    ) -> Result<Arc<Session>, ServerError> {
        // Fast path: try to get existing session (read lock)
        {
            let inner = self
                .inner
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(entry) = inner.sessions.get(session_id) {
                debug!(
                    session_id = %session_id,
                    "reusing existing session"
                );
                return Ok(entry.session.clone());
            }
        }

        // Acquire a session permit to enforce max sessions.
        let permit = self
            .session_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                let current = self
                    .inner
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .sessions
                    .len();
                warn!(
                    current,
                    max = self.max_sessions,
                    "max sessions limit reached"
                );
                ServerError::MaxSessionsReached
            })?;

        // Create new connection in spawn_blocking to avoid blocking async runtime
        // (DuckDB connection creation involves I/O: loading extensions, init SQL, etc.)
        let factory = self.factory.clone();
        let sid = session_id.clone();
        let connection = tokio::task::spawn_blocking(move || {
            let t0 = std::time::Instant::now();
            debug!(session_id = %sid, "creating new connection");
            let conn = factory.create_connection()?;
            info!(
                session_id = %sid,
                total_ms = t0.elapsed().as_millis() as u64,
                "connection created"
            );
            Ok::<_, ServerError>(conn)
        })
        .await
        .map_err(|e| ServerError::Internal(format!("connection task failed: {e}")))??;

        // Create session with the specified ID and a shared Arc connection
        let connection = Arc::new(connection);
        let session = Arc::new(Session::new_with_id_and_auth(
            session_id.clone(),
            connection,
            auth,
        ));

        // Register session
        {
            let mut inner = self
                .inner
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(entry) = inner.sessions.get(session_id) {
                return Ok(entry.session.clone());
            }
            inner.sessions.insert(
                session_id.clone(),
                SessionEntry {
                    session: session.clone(),
                    _permit: permit,
                },
            );
        }
        info!(
            session_id = %session_id,
            total_sessions = self.inner.read().unwrap_or_else(|p| p.into_inner()).sessions.len(),
            "session created with dedicated connection"
        );

        Ok(session)
    }

    /// Interrupt all running queries.
    ///
    /// This is called during server shutdown to stop any long-running queries
    /// so the server can exit promptly.
    pub fn interrupt_all(&self) {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        info!(
            sessions = inner.sessions.len(),
            "interrupting all running queries"
        );
        for (id, entry) in &inner.sessions {
            debug!(session_id = %id, "interrupting session");
            entry.session.connection.interrupt_handle().interrupt();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use anyhow::{anyhow, Result};

    use super::*;

    fn build_registry(
        max_sessions: usize,
        timeout_secs: u64,
    ) -> Result<(SessionRegistry, Arc<EngineFactory>)> {
        let config = ServerConfig {
            max_sessions: Some(max_sessions),
            session_timeout_seconds: Some(timeout_secs),
            ..ServerConfig::default()
        };
        let factory = Arc::new(EngineFactory::new_for_tests(&config));
        let registry = SessionRegistry::new(&config, Arc::clone(&factory))
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok((registry, factory))
    }

    #[test]
    fn snapshot_for_empty_registry_reports_zero_idle_times() -> Result<()> {
        let (registry, _) = build_registry(3, 60)?;
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.total_sessions, 0);
        assert_eq!(snapshot.max_sessions, 3);
        assert_eq!(snapshot.session_timeout_seconds, 60);
        assert_eq!(snapshot.oldest_idle_ms, 0);
        assert_eq!(snapshot.average_idle_ms, 0);
        Ok(())
    }

    #[test]
    fn engine_factory_accessor_returns_registry_factory() -> Result<()> {
        let (registry, factory) = build_registry(3, 60)?;
        let exposed = registry.engine_factory();
        assert!(Arc::ptr_eq(&factory, &exposed));
        Ok(())
    }

    #[tokio::test]
    async fn get_or_create_reuses_existing_session_for_same_id() -> Result<()> {
        let (registry, _) = build_registry(8, 60)?;
        let session_id = SessionId::from_string("peer:reuse".to_string());

        let first = registry
            .get_or_create_by_id(&session_id)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        let second = registry
            .get_or_create_by_id(&session_id)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(registry.snapshot().total_sessions, 1);
        Ok(())
    }

    #[tokio::test]
    async fn get_or_create_returns_max_sessions_error_when_limit_is_reached() -> Result<()> {
        let (registry, _) = build_registry(1, 60)?;
        let first = SessionId::from_string("peer:first".to_string());
        let second = SessionId::from_string("peer:second".to_string());

        let created = registry.get_or_create_by_id(&first).await;
        assert!(created.is_ok());

        let err = registry
            .get_or_create_by_id(&second)
            .await
            .err()
            .ok_or_else(|| anyhow!("expected max-sessions error for second session"))?;
        assert!(matches!(err, ServerError::MaxSessionsReached));
        assert_eq!(registry.snapshot().total_sessions, 1);
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_idle_sessions_removes_only_stale_sessions() -> Result<()> {
        let (registry, _) = build_registry(4, 5)?;
        let stale_id = SessionId::from_string("peer:stale".to_string());
        let fresh_id = SessionId::from_string("peer:fresh".to_string());

        registry
            .get_or_create_by_id(&stale_id)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        registry
            .get_or_create_by_id(&fresh_id)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;

        {
            let mut inner = registry
                .inner
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let stale = inner
                .sessions
                .get_mut(&stale_id)
                .ok_or_else(|| anyhow!("missing stale session"))?;
            let mut last_activity = stale
                .session
                .last_activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *last_activity = Instant::now() - Duration::from_secs(20);
        }

        let removed = registry.cleanup_idle_sessions();
        assert_eq!(removed, 1);

        let inner = registry
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!inner.sessions.contains_key(&stale_id));
        assert!(inner.sessions.contains_key(&fresh_id));
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_same_id_creation_returns_single_session_instance() -> Result<()> {
        let (registry, _) = build_registry(4, 60)?;
        let session_id = SessionId::from_string("peer:concurrent".to_string());

        let left_registry = registry.clone();
        let right_registry = registry.clone();
        let left_id = session_id.clone();
        let right_id = session_id.clone();

        let left = tokio::spawn(async move { left_registry.get_or_create_by_id(&left_id).await });
        let right =
            tokio::spawn(async move { right_registry.get_or_create_by_id(&right_id).await });

        let left_session = left
            .await
            .map_err(|e| anyhow!(e.to_string()))?
            .map_err(|e| anyhow!(e.to_string()))?;
        let right_session = right
            .await
            .map_err(|e| anyhow!(e.to_string()))?
            .map_err(|e| anyhow!(e.to_string()))?;

        assert!(Arc::ptr_eq(&left_session, &right_session));
        assert_eq!(registry.snapshot().total_sessions, 1);
        Ok(())
    }
}
