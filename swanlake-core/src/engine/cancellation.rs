//! Cancellation belongs to one request, including while it waits for a connection.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::ServerError;

#[derive(Default)]
struct State {
    cancelled: bool,
    interrupt: Option<Arc<duckdb::InterruptHandle>>,
}

#[derive(Default)]
pub struct RequestCancellation {
    state: Mutex<State>,
}

impl RequestCancellation {
    pub fn check(&self) -> Result<(), ServerError> {
        if self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cancelled
        {
            Err(ServerError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Call with the connection locked; drop the returned guard BEFORE releasing
    /// that connection. The state mutex serializes the final interrupt with drop.
    pub fn activate(
        &self,
        interrupt: Arc<duckdb::InterruptHandle>,
    ) -> Result<ActiveQuery<'_>, ServerError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.cancelled {
            return Err(ServerError::Cancelled);
        }
        state.interrupt = Some(interrupt);
        Ok(ActiveQuery { cancellation: self })
    }

    pub fn cancel(self: &Arc<Self>) {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.cancelled {
                return;
            }
            state.cancelled = true;
            if state.interrupt.is_none() {
                return; // activate rejects this request when it reaches the lock.
            }
        }
        let cancellation = self.clone();
        tokio::spawn(async move {
            // DuckDB resets its interrupt flag when a statement starts. Repeat
            // while this request owns the connection to cover that startup race.
            while cancellation.interrupt_active() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
    }

    fn interrupt_active(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(interrupt) = &state.interrupt {
            interrupt.interrupt();
            true
        } else {
            false
        }
    }
}

pub struct ActiveQuery<'a> {
    cancellation: &'a RequestCancellation,
}
impl Drop for ActiveQuery<'_> {
    fn drop(&mut self) {
        self.cancellation
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .interrupt = None;
    }
}

/// Held by the RPC future, so disconnects cancel its detached blocking task.
pub struct CancelOnDrop(pub Arc<RequestCancellation>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queued_cancellation_never_arms_an_interrupt() -> anyhow::Result<()> {
        let connection = duckdb::Connection::open_in_memory()?;
        let cancellation = Arc::new(RequestCancellation::default());
        cancellation.cancel();
        assert!(cancellation
            .activate(connection.interrupt_handle())
            .is_err());
        assert!(!cancellation.interrupt_active());
        connection.execute_batch("SELECT 42")?;
        Ok(())
    }

    #[tokio::test]
    async fn completed_request_cannot_interrupt_successor() -> anyhow::Result<()> {
        let connection = duckdb::Connection::open_in_memory()?;
        let cancellation = Arc::new(RequestCancellation::default());
        let active = cancellation.activate(connection.interrupt_handle())?;
        drop(active);
        cancellation.cancel();
        assert!(!cancellation.interrupt_active());
        connection.execute_batch("SELECT sum(i) FROM range(100000) t(i)")?;
        Ok(())
    }
}
