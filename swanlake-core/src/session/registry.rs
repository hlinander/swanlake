//! Session registry - manages all active client sessions.
//!
//! The registry:
//! - Creates new sessions on client connect
//! - Tracks active sessions by ID
//! - Provides session lookup
//! - Cleans up idle sessions
//! - Enforces max session limit
//!
//! When a new session ID is encountered, the connection is reset by creating
//! a fresh DuckDB connection. This ensures each client gets a clean state.

use std::collections::HashMap;

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tracing::{debug, info, instrument, warn};

use crate::config::ServerConfig;
use crate::engine::{DuckDbConnection, EngineFactory};
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
    /// Current session ID - when this changes, we create a fresh connection
    current_session_id: Option<SessionId>,
    /// Shared connection for all sessions with the current session ID
    shared_connection: Arc<DuckDbConnection>,
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

        // Create the initial shared connection
        let shared_connection = Arc::new(factory.lock().unwrap().create_connection()?);
        info!("created initial DuckDB connection");

        info!(
            max_sessions,
            session_timeout_seconds = session_timeout.as_secs(),
            "session registry initialized"
        );

        Ok(Self {
            inner: Arc::new(RwLock::new(RegistryInner {
                sessions: HashMap::new(),
                current_session_id: None,
                shared_connection,
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

    /// Get or create session by session ID
    ///
    /// When a new session ID is encountered (different from current), the connection
    /// is reset by creating a fresh DuckDB connection. This ensures each client
    /// gets a clean state without inherited ATTACHes or other state.
    pub async fn get_or_create_by_id(
        &self,
        session_id: &SessionId,
    ) -> Result<Arc<Session>, ServerError> {
        // First, try to get existing session (read lock)
        {
            let inner = self.inner.read().expect("registry lock poisoned");
            if let Some(session) = inner.sessions.get(session_id) {
                debug!(
                    session_id = %session_id,
                    "reusing existing session"
                );
                return Ok(session.clone());
            }
        }

        // New session ID - need write lock to potentially reset connection
        let mut inner = self.inner.write().expect("registry lock poisoned");

        // Double-check after acquiring write lock
        if let Some(session) = inner.sessions.get(session_id) {
            return Ok(session.clone());
        }

        // Check if this is a different session ID than current
        let need_new_connection = match &inner.current_session_id {
            Some(current) => current != session_id,
            None => false, // First session, use existing connection
        };

        if need_new_connection {
            info!(
                old_session_id = %inner.current_session_id.as_ref().unwrap(),
                new_session_id = %session_id,
                "new session ID detected, creating fresh DuckDB connection"
            );

            // Clear old sessions - they're for a different client
            inner.sessions.clear();

            // Create fresh connection
            let new_connection = Arc::new(
                self.factory
                    .lock()
                    .unwrap()
                    .create_connection()?,
            );
            inner.shared_connection = new_connection;
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

        // Create session with the current shared connection
        let session = Arc::new(Session::new_with_id(
            session_id.clone(),
            inner.shared_connection.clone(),
        ));

        // Register session and update current session ID
        inner.current_session_id = Some(session_id.clone());
        inner.sessions.insert(session_id.clone(), session.clone());
        info!(
            session_id = %session_id,
            total_sessions = inner.sessions.len(),
            "session created"
        );

        Ok(session)
    }

    /// Get the shared connection directly (for operations that need it)
    pub fn shared_connection(&self) -> Arc<DuckDbConnection> {
        let inner = self.inner.read().expect("registry lock poisoned");
        inner.shared_connection.clone()
    }

    /// Interrupt all running queries.
    ///
    /// This is called during server shutdown to stop any long-running queries
    /// so the server can exit promptly.
    pub fn interrupt_all(&self) {
        let inner = self.inner.read().expect("registry lock poisoned");
        info!("interrupting all running queries");
        inner.shared_connection.interrupt_handle().interrupt();
    }
}
