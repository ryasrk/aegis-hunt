use tokio::sync::broadcast;
use crate::types::Event;

/// Event bus for publishing and subscribing to events across all Aegis engines.
/// Uses tokio broadcast channels for fan-out delivery.
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    /// Create a new event bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event to all subscribers. Returns the number of subscribers that received it.
    pub fn emit(&self, event: Event) -> Result<usize, broadcast::error::SendError<Event>> {
        let count = self.tx.send(event)?;
        Ok(count)
    }

    /// Subscribe to all events. Returns a receiver that gets a copy of every emitted event.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}
