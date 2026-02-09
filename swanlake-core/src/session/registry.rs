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

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

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
    factory: Arc<Mutex<EngineFactory>>,
    max_sessions: usize,
    session_timeout: Duration,
}

struct RegistryInner {
    sessions: HashMap<SessionId, Arc<Session>>,
}

impl SessionRegistry {
    /// Create a new session registry
    #[instrument(skip(config, factory))]
    pub fn new(
        config: &ServerConfig,
        factory: Arc<Mutex<EngineFactory>>,
    ) -> Result<Self, ServerError> {
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
        })
    }

    pub fn engine_factory(&self) -> Arc<Mutex<EngineFactory>> {
        self.factory.clone()
    }

    /// Clean up idle sessions that have exceeded the timeout
    #[instrument(skip(self))]
    pub fn cleanup_idle_sessions(&self) -> usize {
        let mut inner = self.inner.write().expect("registry lock poisoned");
        let before = inner.sessions.len();

        inner.sessions.retain(|id, session| {
            if session.idle_duration() > self.session_timeout {
                info!(
                    session_id = %id,
                    idle_duration = ?session.idle_duration(),
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

    /// Get or create session by session ID.
    ///
    /// Each session ID gets its own dedicated DuckDB connection, providing
    /// full isolation between clients (separate catalogs, transactions,
    /// temp tables, etc.).
    pub async fn get_or_create_by_id(
        &self,
        session_id: &SessionId,
    ) -> Result<Arc<Session>, ServerError> {
        // Fast path: try to get existing session (read lock)
        {
            let inner = self.inner.read().expect("registry lock poisoned");
            if let Some(session) = inner.sessions.get(session_id) {
                debug!(session_id = %session_id, "reusing existing session");
                return Ok(session.clone());
            }
        }

        // Slow path: need write lock to create new session
        let mut inner = self.inner.write().expect("registry lock poisoned");

        // Double-check after acquiring write lock
        if let Some(session) = inner.sessions.get(session_id) {
            return Ok(session.clone());
        }

        // Check session limit
        if inner.sessions.len() >= self.max_sessions {
            warn!(
                current = inner.sessions.len(),
                max = self.max_sessions,
                "max sessions limit reached"
            );
            return Err(ServerError::MaxSessionsReached);
        }

        // Create a dedicated connection for this session
        let connection = Arc::new(
            self.factory
                .lock()
                .unwrap()
                .create_connection()?,
        );

        let session = Arc::new(Session::new_with_id(
            session_id.clone(),
            connection,
        ));

        inner.sessions.insert(session_id.clone(), session.clone());
        info!(
            session_id = %session_id,
            total_sessions = inner.sessions.len(),
            "session created with dedicated connection"
        );

        Ok(session)
    }

    /// Interrupt all running queries.
    ///
    /// This is called during server shutdown to stop any long-running queries
    /// so the server can exit promptly.
    pub fn interrupt_all(&self) {
        let inner = self.inner.read().expect("registry lock poisoned");
        info!(
            sessions = inner.sessions.len(),
            "interrupting all running queries"
        );
        for (id, session) in &inner.sessions {
            debug!(session_id = %id, "interrupting session");
            session.connection.interrupt_handle().interrupt();
        }
    }

    /// Number of active sessions (for testing/monitoring).
    #[cfg(test)]
    fn session_count(&self) -> usize {
        self.inner.read().expect("registry lock poisoned").sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry(max_sessions: usize) -> SessionRegistry {
        let factory = Arc::new(Mutex::new(EngineFactory::new_for_test()));
        SessionRegistry {
            inner: Arc::new(RwLock::new(RegistryInner {
                sessions: HashMap::new(),
            })),
            factory,
            max_sessions,
            session_timeout: Duration::from_secs(1),
        }
    }

    fn session_id(name: &str) -> SessionId {
        SessionId::from_string(name.to_string())
    }

    #[tokio::test]
    async fn session_reuse_returns_same_instance() {
        let registry = test_registry(10);
        let id = session_id("client-a");

        let s1 = registry.get_or_create_by_id(&id).await.unwrap();
        let s2 = registry.get_or_create_by_id(&id).await.unwrap();

        assert!(Arc::ptr_eq(&s1, &s2));
    }

    #[tokio::test]
    async fn different_clients_get_independent_connections() {
        let registry = test_registry(10);

        let sa = registry.get_or_create_by_id(&session_id("client-a")).await.unwrap();
        let sb = registry.get_or_create_by_id(&session_id("client-b")).await.unwrap();

        // Different session objects
        assert!(!Arc::ptr_eq(&sa, &sb));
        // Different underlying DuckDB connections
        assert!(!Arc::ptr_eq(&sa.connection, &sb.connection));
    }

    #[tokio::test]
    async fn new_session_does_not_evict_existing() {
        let registry = test_registry(10);
        let id_a = session_id("client-a");
        let id_b = session_id("client-b");

        let sa = registry.get_or_create_by_id(&id_a).await.unwrap();
        let _sb = registry.get_or_create_by_id(&id_b).await.unwrap();

        // Client A's session must still be there and be the same instance
        let sa_again = registry.get_or_create_by_id(&id_a).await.unwrap();
        assert!(Arc::ptr_eq(&sa, &sa_again));
        assert_eq!(registry.session_count(), 2);
    }

    #[tokio::test]
    async fn max_sessions_enforced() {
        let registry = test_registry(2);

        registry.get_or_create_by_id(&session_id("a")).await.unwrap();
        registry.get_or_create_by_id(&session_id("b")).await.unwrap();

        let result = registry.get_or_create_by_id(&session_id("c")).await;
        assert!(matches!(result, Err(ServerError::MaxSessionsReached)));
    }

    #[tokio::test]
    async fn idle_cleanup_removes_expired_but_keeps_active() {
        let registry = test_registry(10);

        let id_old = session_id("old-client");
        let id_new = session_id("new-client");

        registry.get_or_create_by_id(&id_old).await.unwrap();

        // Wait for the old session to expire (timeout = 1s)
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // Create a fresh session that should survive cleanup
        registry.get_or_create_by_id(&id_new).await.unwrap();

        let removed = registry.cleanup_idle_sessions();
        assert_eq!(removed, 1);
        assert_eq!(registry.session_count(), 1);

        // The surviving session should be the new one
        let surviving = registry.get_or_create_by_id(&id_new).await.unwrap();
        assert!(Arc::ptr_eq(
            &surviving,
            &registry.get_or_create_by_id(&id_new).await.unwrap()
        ));
    }

    #[tokio::test]
    async fn connection_isolation_between_clients() {
        let registry = test_registry(10);

        let sa = registry.get_or_create_by_id(&session_id("client-a")).await.unwrap();
        let sb = registry.get_or_create_by_id(&session_id("client-b")).await.unwrap();

        // Create a table in session A's connection
        sa.execute_statement("CREATE TABLE isolation_test (id INTEGER)").unwrap();

        // Session B must NOT see it — separate in-memory database
        let result = sa.execute_query("SELECT * FROM isolation_test");
        assert!(result.is_ok());

        let result = sb.execute_query("SELECT * FROM isolation_test");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn interrupt_all_with_multiple_sessions() {
        let registry = test_registry(10);

        registry.get_or_create_by_id(&session_id("a")).await.unwrap();
        registry.get_or_create_by_id(&session_id("b")).await.unwrap();
        registry.get_or_create_by_id(&session_id("c")).await.unwrap();

        // Should not panic — interrupts all three connections
        registry.interrupt_all();
    }
}
