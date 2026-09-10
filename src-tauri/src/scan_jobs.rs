use crate::{
    database::utc_now,
    error::AppError,
    models::{ScanJobState, ScanJobStatus, ScanJobStep, StepStatus},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

const MAX_RETAINED_JOBS: usize = 200;

struct ManagedJob {
    state: ScanJobState,
    cancellation: Arc<AtomicBool>,
}

#[derive(Default)]
struct JobState {
    jobs: HashMap<String, ManagedJob>,
    order: VecDeque<String>,
    active_by_site: HashMap<String, String>,
}

struct ConcurrencyGate {
    active: Mutex<usize>,
    changed: Condvar,
    limit: AtomicUsize,
}

#[derive(Clone)]
pub struct ScanJobManager {
    state: Arc<Mutex<JobState>>,
    gate: Arc<ConcurrencyGate>,
}

pub struct ScanPermit {
    gate: Arc<ConcurrencyGate>,
}

impl Drop for ScanPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.gate.active.lock() {
            *active = active.saturating_sub(1);
            self.gate.changed.notify_one();
        }
    }
}

impl ScanJobManager {
    pub fn new(concurrency: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(JobState::default())),
            gate: Arc::new(ConcurrencyGate {
                active: Mutex::new(0),
                changed: Condvar::new(),
                limit: AtomicUsize::new(concurrency.clamp(1, 5)),
            }),
        }
    }

    pub fn set_concurrency(&self, concurrency: usize) {
        self.gate
            .limit
            .store(concurrency.clamp(1, 5), Ordering::SeqCst);
        self.gate.changed.notify_all();
    }

    pub fn create_site_scan(
        &self,
        site_id: &str,
        site_name: &str,
        steps: &[(&str, &str)],
    ) -> Result<(ScanJobState, bool), AppError> {
        let mut state = self.lock()?;
        if let Some(existing_id) = state.active_by_site.get(site_id)
            && let Some(existing) = state.jobs.get(existing_id)
            && existing.state.status.is_active()
        {
            return Ok((existing.state.clone(), false));
        }
        let job_id = Uuid::new_v4().to_string();
        let job = ScanJobState {
            id: job_id.clone(),
            job_type: "site_scan".into(),
            site_id: site_id.into(),
            site_name: site_name.into(),
            status: ScanJobStatus::Queued,
            created_at: utc_now(),
            started_at: None,
            finished_at: None,
            current_step: None,
            completed_steps: 0,
            total_steps: steps.len(),
            cancellation_requested: false,
            result_scan_id: None,
            error: None,
            steps: steps
                .iter()
                .map(|(key, label)| ScanJobStep {
                    key: (*key).into(),
                    label: (*label).into(),
                    status: StepStatus::Pending,
                    started_at: None,
                    duration_ms: None,
                    detail: None,
                })
                .collect(),
        };
        state.active_by_site.insert(site_id.into(), job_id.clone());
        state.order.push_back(job_id.clone());
        state.jobs.insert(
            job_id,
            ManagedJob {
                state: job.clone(),
                cancellation: Arc::new(AtomicBool::new(false)),
            },
        );
        Self::prune(&mut state);
        Ok((job, true))
    }

    pub fn get(&self, job_id: &str) -> Result<ScanJobState, AppError> {
        self.lock()?
            .jobs
            .get(job_id)
            .map(|job| job.state.clone())
            .ok_or_else(|| AppError::not_found("Scantaak"))
    }

    pub fn for_site(&self, site_id: &str) -> Result<Option<ScanJobState>, AppError> {
        let state = self.lock()?;
        let job = state
            .active_by_site
            .get(site_id)
            .and_then(|job_id| state.jobs.get(job_id))
            .or_else(|| {
                state.order.iter().rev().find_map(|job_id| {
                    state
                        .jobs
                        .get(job_id)
                        .filter(|job| job.state.site_id == site_id)
                })
            });
        Ok(job.map(|job| job.state.clone()))
    }

    pub fn list(&self, active_only: bool) -> Result<Vec<ScanJobState>, AppError> {
        let state = self.lock()?;
        Ok(state
            .order
            .iter()
            .rev()
            .filter_map(|job_id| state.jobs.get(job_id))
            .filter(|job| !active_only || job.state.status.is_active())
            .map(|job| job.state.clone())
            .collect())
    }

    pub fn cancellation(&self, job_id: &str) -> Result<Arc<AtomicBool>, AppError> {
        self.lock()?
            .jobs
            .get(job_id)
            .map(|job| Arc::clone(&job.cancellation))
            .ok_or_else(|| AppError::not_found("Scantaak"))
    }

    pub fn cancel(&self, job_id: &str) -> Result<ScanJobState, AppError> {
        let mut state = self.lock()?;
        let site_id;
        let snapshot;
        {
            let job = state
                .jobs
                .get_mut(job_id)
                .ok_or_else(|| AppError::not_found("Scantaak"))?;
            job.cancellation.store(true, Ordering::SeqCst);
            job.state.cancellation_requested = true;
            if job.state.status == ScanJobStatus::Queued {
                job.state.status = ScanJobStatus::Cancelled;
                job.state.finished_at = Some(utc_now());
            }
            site_id = job.state.site_id.clone();
            snapshot = job.state.clone();
        }
        if !snapshot.status.is_active() {
            state.active_by_site.remove(&site_id);
        }
        self.gate.changed.notify_all();
        Ok(snapshot)
    }

    pub fn mark_running(&self, job_id: &str) -> Result<ScanJobState, AppError> {
        self.update(job_id, |job| {
            job.status = ScanJobStatus::Running;
            job.started_at = Some(utc_now());
        })
    }

    pub fn step_started(&self, job_id: &str, key: &str) -> Result<ScanJobState, AppError> {
        self.update(job_id, |job| {
            job.current_step = Some(key.into());
            if let Some(step) = job.steps.iter_mut().find(|step| step.key == key) {
                step.status = StepStatus::Running;
                step.started_at = Some(utc_now());
                step.detail = None;
            }
        })
    }

    pub fn step_finished(
        &self,
        job_id: &str,
        key: &str,
        status: StepStatus,
        duration_ms: u64,
        detail: Option<String>,
    ) -> Result<ScanJobState, AppError> {
        self.update(job_id, |job| {
            if let Some(step) = job.steps.iter_mut().find(|step| step.key == key) {
                step.status = status;
                step.duration_ms = Some(duration_ms);
                step.detail = detail;
            }
            job.completed_steps = job
                .steps
                .iter()
                .filter(|step| !matches!(step.status, StepStatus::Pending | StepStatus::Running))
                .count();
        })
    }

    pub fn complete(&self, job_id: &str, scan_id: &str) -> Result<ScanJobState, AppError> {
        self.finish(job_id, ScanJobStatus::Completed, Some(scan_id.into()), None)
    }

    pub fn fail(&self, job_id: &str, error: AppError) -> Result<ScanJobState, AppError> {
        self.finish(job_id, ScanJobStatus::Failed, None, Some(error))
    }

    pub fn mark_cancelled(&self, job_id: &str) -> Result<ScanJobState, AppError> {
        self.finish(job_id, ScanJobStatus::Cancelled, None, None)
    }

    pub fn acquire(&self, cancellation: &AtomicBool) -> Result<Option<ScanPermit>, AppError> {
        let mut active = self
            .gate
            .active
            .lock()
            .map_err(|_| AppError::storage("Scan concurrency lock poisoned"))?;
        loop {
            if cancellation.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let limit = self.gate.limit.load(Ordering::SeqCst).clamp(1, 5);
            if *active < limit {
                *active += 1;
                return Ok(Some(ScanPermit {
                    gate: Arc::clone(&self.gate),
                }));
            }
            let (next, _) = self
                .gate
                .changed
                .wait_timeout(active, Duration::from_millis(100))
                .map_err(|_| AppError::storage("Scan concurrency lock poisoned"))?;
            active = next;
        }
    }

    fn finish(
        &self,
        job_id: &str,
        status: ScanJobStatus,
        scan_id: Option<String>,
        error: Option<AppError>,
    ) -> Result<ScanJobState, AppError> {
        let mut state = self.lock()?;
        let site_id;
        let snapshot;
        {
            let job = state
                .jobs
                .get_mut(job_id)
                .ok_or_else(|| AppError::not_found("Scantaak"))?;
            job.state.status = status;
            job.state.finished_at = Some(utc_now());
            job.state.current_step = None;
            job.state.result_scan_id = scan_id;
            job.state.error = error;
            site_id = job.state.site_id.clone();
            snapshot = job.state.clone();
        }
        state.active_by_site.remove(&site_id);
        Ok(snapshot)
    }

    fn update(
        &self,
        job_id: &str,
        update: impl FnOnce(&mut ScanJobState),
    ) -> Result<ScanJobState, AppError> {
        let mut state = self.lock()?;
        let job = state
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| AppError::not_found("Scantaak"))?;
        update(&mut job.state);
        Ok(job.state.clone())
    }

    fn prune(state: &mut JobState) {
        while state.order.len() > MAX_RETAINED_JOBS {
            let Some(position) = state.order.iter().position(|job_id| {
                state
                    .jobs
                    .get(job_id)
                    .is_none_or(|job| !job.state.status.is_active())
            }) else {
                break;
            };
            if let Some(job_id) = state.order.remove(position) {
                state.jobs.remove(&job_id);
            }
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, JobState>, AppError> {
        self.state
            .lock()
            .map_err(|_| AppError::storage("Scan job lock poisoned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    const STEPS: &[(&str, &str)] = &[("ssh", "SSH"), ("persist", "Opslaan")];

    #[test]
    fn start_is_immediate_and_duplicate_site_scan_reuses_active_job() {
        let manager = ScanJobManager::new(2);
        let started = Instant::now();
        let (first, created) = manager.create_site_scan("site-a", "Site A", STEPS).unwrap();
        assert!(created);
        eprintln!("background_job_start_us={}", started.elapsed().as_micros());
        assert!(started.elapsed() < Duration::from_millis(100));
        let (duplicate, created) = manager.create_site_scan("site-a", "Site A", STEPS).unwrap();
        assert!(!created);
        assert_eq!(duplicate.id, first.id);
    }

    #[test]
    fn job_transitions_from_queued_to_running_to_completed() {
        let manager = ScanJobManager::new(1);
        let (job, _) = manager.create_site_scan("site-a", "Site A", STEPS).unwrap();
        assert_eq!(job.status, ScanJobStatus::Queued);
        assert_eq!(
            manager.mark_running(&job.id).unwrap().status,
            ScanJobStatus::Running
        );
        manager.step_started(&job.id, "ssh").unwrap();
        let progress = manager
            .step_finished(&job.id, "ssh", StepStatus::Success, 42, None)
            .unwrap();
        assert_eq!(progress.completed_steps, 1);
        let complete = manager.complete(&job.id, "scan-a").unwrap();
        assert_eq!(complete.status, ScanJobStatus::Completed);
        assert_eq!(complete.result_scan_id.as_deref(), Some("scan-a"));
    }

    #[test]
    fn queued_and_running_jobs_can_be_cancelled() {
        let manager = ScanJobManager::new(1);
        let (queued, _) = manager.create_site_scan("site-a", "Site A", STEPS).unwrap();
        assert_eq!(
            manager.cancel(&queued.id).unwrap().status,
            ScanJobStatus::Cancelled
        );
        let (running, _) = manager.create_site_scan("site-a", "Site A", STEPS).unwrap();
        manager.mark_running(&running.id).unwrap();
        let requested = manager.cancel(&running.id).unwrap();
        assert_eq!(requested.status, ScanJobStatus::Running);
        assert!(requested.cancellation_requested);
        assert!(
            manager
                .cancellation(&running.id)
                .unwrap()
                .load(Ordering::SeqCst)
        );
        assert_eq!(
            manager.mark_cancelled(&running.id).unwrap().status,
            ScanJobStatus::Cancelled
        );
    }

    #[test]
    fn concurrency_gate_never_exceeds_the_configured_limit() {
        let manager = ScanJobManager::new(1);
        let first_cancellation = AtomicBool::new(false);
        let first = manager.acquire(&first_cancellation).unwrap().unwrap();
        let (sender, receiver) = mpsc::channel();
        let worker_manager = manager.clone();
        let worker = std::thread::spawn(move || {
            let cancellation = AtomicBool::new(false);
            let _permit = worker_manager.acquire(&cancellation).unwrap().unwrap();
            sender.send(()).unwrap();
        });

        assert!(receiver.recv_timeout(Duration::from_millis(75)).is_err());
        drop(first);
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }
}
