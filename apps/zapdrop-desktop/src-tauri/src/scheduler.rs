use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

pub const MAX_SCHEDULER_RECIPIENTS: usize = 8;
pub const MAX_SCHEDULER_QUEUE: usize = 64;
pub const MAX_SCHEDULER_RETRIES: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmSchedulerOptions {
    #[serde(default = "default_parallel_recipients")]
    pub max_parallel_recipients: usize,
    #[serde(default = "default_queue_limit")]
    pub queue_limit: usize,
    #[serde(default)]
    pub bandwidth_bytes_per_second: u64,
    #[serde(default)]
    pub max_retries: u8,
}

impl Default for SwarmSchedulerOptions {
    fn default() -> Self {
        Self {
            max_parallel_recipients: default_parallel_recipients(),
            queue_limit: default_queue_limit(),
            bandwidth_bytes_per_second: 0,
            max_retries: 0,
        }
    }
}

impl SwarmSchedulerOptions {
    pub fn validate(&self) -> io::Result<()> {
        if self.max_parallel_recipients == 0
            || self.max_parallel_recipients > MAX_SCHEDULER_RECIPIENTS
        {
            return Err(invalid(
                "parallel recipient limit is outside the supported range",
            ));
        }
        if self.queue_limit > MAX_SCHEDULER_QUEUE {
            return Err(invalid(
                "scheduler queue limit is outside the supported range",
            ));
        }
        if self.max_retries > MAX_SCHEDULER_RETRIES {
            return Err(invalid("retry limit is outside the supported range"));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SchedulerState {
    active: usize,
    waiting: VecDeque<u64>,
    next_ticket: u64,
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct SwarmScheduler {
    options: SwarmSchedulerOptions,
    state: Mutex<SchedulerState>,
    changed: Condvar,
}

impl SwarmScheduler {
    pub fn new(options: SwarmSchedulerOptions) -> io::Result<Arc<Self>> {
        options.validate()?;
        Ok(Arc::new(Self {
            state: Mutex::new(SchedulerState {
                active: 0,
                waiting: VecDeque::new(),
                next_ticket: 0,
                tokens: options.bandwidth_bytes_per_second as f64,
                last_refill: Instant::now(),
            }),
            changed: Condvar::new(),
            options,
        }))
    }

    pub fn options(&self) -> &SwarmSchedulerOptions {
        &self.options
    }

    pub fn acquire(self: &Arc<Self>, peer_id: &str) -> io::Result<SwarmPermit> {
        let _ = peer_id;
        let mut state = self.state.lock().expect("scheduler state poisoned");
        let can_start_immediately =
            state.waiting.is_empty() && state.active < self.options.max_parallel_recipients;
        if !can_start_immediately && state.waiting.len() >= self.options.queue_limit {
            return Err(invalid("swarm scheduler queue is full"));
        }
        let ticket = state.next_ticket;
        state.next_ticket = state.next_ticket.wrapping_add(1);
        state.waiting.push_back(ticket);
        loop {
            let at_front = state.waiting.front().copied() == Some(ticket);
            if at_front && state.active < self.options.max_parallel_recipients {
                state.waiting.pop_front();
                state.active += 1;
                return Ok(SwarmPermit {
                    scheduler: Arc::clone(self),
                });
            }
            state = self
                .changed
                .wait(state)
                .expect("scheduler condition variable poisoned");
        }
    }

    pub fn throttle(&self, bytes: usize) {
        let rate = self.options.bandwidth_bytes_per_second as f64;
        if rate == 0.0 || bytes == 0 {
            return;
        }
        loop {
            let wait = {
                let mut state = self.state.lock().expect("scheduler state poisoned");
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill).as_secs_f64();
                state.tokens = (state.tokens + elapsed * rate).min(rate);
                state.last_refill = now;
                let requested = bytes as f64;
                if state.tokens >= requested {
                    state.tokens -= requested;
                    return;
                }
                (requested - state.tokens) / rate
            };
            thread::sleep(Duration::from_secs_f64(wait.min(1.0).max(0.001)));
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("scheduler state poisoned");
        state.active = state.active.saturating_sub(1);
        self.changed.notify_all();
    }
}

pub struct SwarmPermit {
    scheduler: Arc<SwarmScheduler>,
}

impl Drop for SwarmPermit {
    fn drop(&mut self) {
        self.scheduler.release();
    }
}

fn default_parallel_recipients() -> usize {
    4
}

fn default_queue_limit() -> usize {
    16
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn rejects_unbounded_scheduler_options() {
        assert!(SwarmScheduler::new(SwarmSchedulerOptions {
            max_parallel_recipients: 0,
            ..Default::default()
        })
        .is_err());
        assert!(SwarmScheduler::new(SwarmSchedulerOptions {
            queue_limit: MAX_SCHEDULER_QUEUE + 1,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn zero_waiting_queue_still_allows_immediate_admission() {
        let scheduler = SwarmScheduler::new(SwarmSchedulerOptions {
            max_parallel_recipients: 1,
            queue_limit: 0,
            ..Default::default()
        })
        .unwrap();
        let permit = scheduler.acquire("peer-1").unwrap();
        assert!(scheduler.acquire("peer-2").is_err());
        drop(permit);
        assert!(scheduler.acquire("peer-3").is_ok());
    }

    #[test]
    fn bounds_active_recipients_and_releases_permits() {
        let scheduler = SwarmScheduler::new(SwarmSchedulerOptions {
            max_parallel_recipients: 2,
            queue_limit: 4,
            ..Default::default()
        })
        .unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for index in 0..4 {
            let scheduler = Arc::clone(&scheduler);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            workers.push(thread::spawn(move || {
                let permit = scheduler.acquire(&format!("peer-{index}")).unwrap();
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(5));
                active.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
