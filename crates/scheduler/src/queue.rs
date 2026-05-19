use std::sync::mpsc;
use std::sync::Mutex;
use tracing::debug;

/// Priority levels for the scheduler queues.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueuePriority {
    Fast,      // DNS, HEAD requests, favicon hashing
    Medium,    // Crawling, JS analysis, endpoint extraction
    Expensive, // Deep nuclei, authenticated workflows, complex verification
    Human,     // Manual validation, exploit review, bounty submission
}

impl QueuePriority {
    pub fn from_risk_score(score: u32) -> Self {
        match score {
            0..=30 => QueuePriority::Fast,
            31..=60 => QueuePriority::Medium,
            61..=100 => QueuePriority::Expensive,
            _ => QueuePriority::Human,
        }
    }
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

impl QueueItem {
    pub fn new(task_type: impl Into<String>, target: impl Into<String>, priority: QueuePriority) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            task_type: task_type.into(),
            target: target.into(),
            payload: String::new(),
            priority,
        }
    }

    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = payload.into();
        self
    }
}

/// Priority-based queue system with 4 levels.
///
/// Uses `Mutex<Receiver>` internally so `PriorityQueue` is `Sync`,
/// allowing safe sharing across async boundaries.
pub struct PriorityQueue {
    fast_tx: mpsc::Sender<QueueItem>,
    fast_rx: Mutex<mpsc::Receiver<QueueItem>>,
    medium_tx: mpsc::Sender<QueueItem>,
    medium_rx: Mutex<mpsc::Receiver<QueueItem>>,
    expensive_tx: mpsc::Sender<QueueItem>,
    expensive_rx: Mutex<mpsc::Receiver<QueueItem>>,
    human_tx: mpsc::Sender<QueueItem>,
    human_rx: Mutex<mpsc::Receiver<QueueItem>>,
}

impl PriorityQueue {
    pub fn new() -> Self {
        let (fast_tx, fast_rx) = mpsc::channel();
        let (medium_tx, medium_rx) = mpsc::channel();
        let (expensive_tx, expensive_rx) = mpsc::channel();
        let (human_tx, human_rx) = mpsc::channel();
        Self {
            fast_tx, fast_rx: Mutex::new(fast_rx),
            medium_tx, medium_rx: Mutex::new(medium_rx),
            expensive_tx, expensive_rx: Mutex::new(expensive_rx),
            human_tx, human_rx: Mutex::new(human_rx),
        }
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
        self.fast_rx.lock().ok().and_then(|rx| rx.try_recv().ok())
            .or_else(|| self.medium_rx.lock().ok().and_then(|rx| rx.try_recv().ok()))
            .or_else(|| self.expensive_rx.lock().ok().and_then(|rx| rx.try_recv().ok()))
            .or_else(|| self.human_rx.lock().ok().and_then(|rx| rx.try_recv().ok()))
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new()
    }
}
