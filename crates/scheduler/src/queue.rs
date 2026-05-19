use std::sync::mpsc;
use tracing::debug;

/// Priority levels for the scheduler queues.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueuePriority {
    Fast,      // DNS, HEAD requests, favicon hashing
    Medium,    // Crawling, JS analysis, endpoint extraction
    Expensive, // Deep nuclei, authenticated workflows, complex verification
    Human,     // Manual validation, exploit review, bounty submission
}

/// An item enqueued for processing.
#[derive(Debug, Clone)]
pub struct QueueItem {
    pub id: String,
    pub task_type: String,
    pub target: String,
    pub payload: String,
    pub priority: QueuePriority,
}

/// Priority-based queue system with 4 levels.
pub struct PriorityQueue {
    fast_tx: mpsc::Sender<QueueItem>,
    fast_rx: mpsc::Receiver<QueueItem>,
    medium_tx: mpsc::Sender<QueueItem>,
    medium_rx: mpsc::Receiver<QueueItem>,
    expensive_tx: mpsc::Sender<QueueItem>,
    expensive_rx: mpsc::Receiver<QueueItem>,
    human_tx: mpsc::Sender<QueueItem>,
    human_rx: mpsc::Receiver<QueueItem>,
}

impl PriorityQueue {
    pub fn new() -> Self {
        let (fast_tx, fast_rx) = mpsc::channel();
        let (medium_tx, medium_rx) = mpsc::channel();
        let (expensive_tx, expensive_rx) = mpsc::channel();
        let (human_tx, human_rx) = mpsc::channel();
        Self { fast_tx, fast_rx, medium_tx, medium_rx, expensive_tx, expensive_rx, human_tx, human_rx }
    }

    pub fn enqueue(&self, item: QueueItem) {
        debug!("Enqueuing {} task: {}", item.task_type, item.target);
        match item.priority {
            QueuePriority::Fast => { let _ = self.fast_tx.send(item); }
            QueuePriority::Medium => { let _ = self.medium_tx.send(item); }
            QueuePriority::Expensive => { let _ = self.expensive_tx.send(item); }
            QueuePriority::Human => { let _ = self.human_tx.send(item); }
        }
    }

    /// Dequeue the highest-priority available item (Fast > Medium > Expensive > Human).
    pub fn dequeue(&self) -> Option<QueueItem> {
        self.fast_rx.try_recv()
            .or_else(|_| self.medium_rx.try_recv())
            .or_else(|_| self.expensive_rx.try_recv())
            .or_else(|_| self.human_rx.try_recv())
            .ok()
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new()
    }
}
