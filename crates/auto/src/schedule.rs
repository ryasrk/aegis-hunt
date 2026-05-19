use std::collections::HashMap;
use std::sync::Mutex;
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScheduledTask {
    pub id: String,
    pub target: String,
    pub interval_minutes: u64,
    pub next_run: DateTime<Utc>,
    pub last_run: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub campaign_id: Option<String>,
}

pub struct Scheduler {
    tasks: Mutex<HashMap<String, ScheduledTask>>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self { tasks: Mutex::new(HashMap::new()) }
    }

    /// Schedule recurring scans for a target.
    pub fn schedule(&self, target: &str, interval_minutes: u64) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let task = ScheduledTask {
            id: id.clone(),
            target: target.to_string(),
            interval_minutes,
            next_run: Utc::now() + Duration::minutes(interval_minutes as i64),
            last_run: None,
            enabled: true,
            campaign_id: None,
        };
        self.tasks.lock().unwrap().insert(id.clone(), task);
        id
    }

    /// Get all tasks that are due for execution.
    pub fn due_tasks(&self) -> Vec<ScheduledTask> {
        let now = Utc::now();
        self.tasks.lock().unwrap().values()
            .filter(|t| t.enabled && t.next_run <= now)
            .cloned()
            .collect()
    }

    /// Mark a task as completed for this interval.
    pub fn complete_run(&self, task_id: &str, campaign_id: &str) {
        if let Some(task) = self.tasks.lock().unwrap().get_mut(task_id) {
            task.last_run = Some(Utc::now());
            task.next_run = Utc::now() + Duration::minutes(task.interval_minutes as i64);
            task.campaign_id = Some(campaign_id.to_string());
        }
    }

    /// Enable or disable a task.
    pub fn set_enabled(&self, task_id: &str, enabled: bool) {
        if let Some(task) = self.tasks.lock().unwrap().get_mut(task_id) {
            task.enabled = enabled;
        }
    }

    /// List all scheduled tasks.
    pub fn list_tasks(&self) -> Vec<ScheduledTask> {
        self.tasks.lock().unwrap().values().cloned().collect()
    }

    pub fn remove(&self, task_id: &str) {
        self.tasks.lock().unwrap().remove(task_id);
    }
}

impl Default for Scheduler { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_task() {
        let sched = Scheduler::new();
        let _id = sched.schedule("example.com", 60);
        assert!(sched.list_tasks().len() == 1);

        let task = sched.list_tasks().into_iter().next().unwrap();
        assert_eq!(task.target, "example.com");
        assert_eq!(task.interval_minutes, 60);
        assert!(task.enabled);
    }

    #[test]
    fn test_due_tasks_empty_initially() {
        let sched = Scheduler::new();
        assert!(sched.due_tasks().is_empty());
    }

    #[test]
    fn test_complete_run() {
        let sched = Scheduler::new();
        let id = sched.schedule("example.com", 60);
        sched.complete_run(&id, "campaign-123");
        let task = sched.list_tasks().into_iter().next().unwrap();
        assert!(task.last_run.is_some());
        assert_eq!(task.campaign_id.unwrap(), "campaign-123");
    }

    #[test]
    fn test_disable_task() {
        let sched = Scheduler::new();
        let id = sched.schedule("example.com", 60);
        sched.set_enabled(&id, false);
        let task = sched.list_tasks().into_iter().next().unwrap();
        assert!(!task.enabled);
    }

    #[test]
    fn test_remove_task() {
        let sched = Scheduler::new();
        let id = sched.schedule("example.com", 60);
        sched.remove(&id);
        assert!(sched.list_tasks().is_empty());
    }
}
