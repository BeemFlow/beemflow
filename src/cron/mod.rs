//! Built-in cron scheduler for automatic flow execution.
//!
//! Schedules deployed flows with `on: schedule.cron` triggers using
//! `tokio-cron-scheduler`. Jobs directly invoke the engine without HTTP overhead.
//!
//! # Performance
//!
//! Optimized for 1000+ deployed flows:
//! - Uses indexed `flow_triggers` table for O(log N) queries
//! - Incremental updates via `add_schedule()` and `remove_schedule()`
//! - Parallel deployments: per-flow granularity
//!
//! # Example
//!
//! ```rust,no_run
//! use beemflow::cron::CronManager;
//! use beemflow::storage::Storage;
//! use beemflow::Engine;
//! use std::sync::Arc;
//!
//! # async fn example(storage: Arc<dyn Storage>, engine: Arc<Engine>) -> beemflow::Result<()> {
//! // Create and start scheduler
//! let cron = CronManager::new(storage, engine).await?;
//!
//! // Full sync on startup
//! let report = cron.sync().await?;
//! println!("Scheduled {} flows", report.scheduled.len());
//!
//! // Add/update schedule for a flow
//! cron.add_schedule("my_flow").await?;
//!
//! // Remove schedule for a flow
//! cron.remove_schedule("my_flow").await?;
//!
//! // Gracefully shutdown on exit
//! cron.shutdown().await?;
//! # Ok(())
//! # }
//! ```

use crate::dsl::parse_string;
use crate::engine::Engine;
use crate::model::Flow;
use crate::storage::Storage;
use crate::{BeemFlowError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_cron_scheduler::{Job, JobScheduler};
use uuid::Uuid;

/// Manages cron scheduling for deployed flows.
///
/// CronManager maintains an in-memory job scheduler that syncs with
/// deployed flows in storage. Jobs are tracked by UUID for efficient updates.
///
/// # Thread Safety
///
/// CronManager is typically wrapped in `Arc` in Dependencies, so the Mutex
/// fields provide interior mutability for the shared scheduler and jobs map.
pub struct CronManager {
    storage: Arc<dyn Storage>,
    engine: Arc<Engine>,
    /// Scheduler wrapped in Mutex for interior mutability (shutdown requires &mut)
    scheduler: Mutex<JobScheduler>,
    /// Maps flow names to scheduled job UUIDs for efficient updates
    jobs: Mutex<HashMap<String, Uuid>>,
}

impl CronManager {
    /// Create and start a new cron manager.
    ///
    /// The scheduler is started immediately and ready to accept jobs.
    /// Call `sync()` to load jobs from deployed flows.
    ///
    /// # Errors
    ///
    /// Returns error if scheduler creation or startup fails.
    pub async fn new(storage: Arc<dyn Storage>, engine: Arc<Engine>) -> Result<Self> {
        let scheduler = JobScheduler::new()
            .await
            .map_err(|e| BeemFlowError::config(format!("Failed to create job scheduler: {}", e)))?;

        scheduler
            .start()
            .await
            .map_err(|e| BeemFlowError::config(format!("Failed to start job scheduler: {}", e)))?;

        tracing::info!("Cron scheduler started");

        Ok(Self {
            storage,
            engine,
            scheduler: Mutex::new(scheduler),
            jobs: Mutex::new(HashMap::new()),
        })
    }

    /// Full synchronization with all deployed cron flows.
    ///
    /// Called once on server startup to load all cron-triggered flows.
    /// Uses indexed query to find flows with `schedule.cron` trigger.
    ///
    /// # Performance
    ///
    /// For 1000 deployed flows with 10 cron triggers: ~1ms
    ///
    /// # Errors
    ///
    /// Returns error if storage query or scheduler operations fail.
    /// Individual flow parsing errors are reported in `SyncReport.errors`.
    pub async fn sync(&self) -> Result<SyncReport> {
        let mut report = SyncReport::default();

        // Query flows with schedule.cron trigger (O(log N) indexed lookup)
        let cron_flow_names = self
            .storage
            .find_flow_names_by_topic("schedule.cron")
            .await?;

        tracing::debug!(
            count = cron_flow_names.len(),
            "Found flows with schedule.cron trigger"
        );

        if cron_flow_names.is_empty() {
            tracing::info!("No cron-triggered flows found");
            return Ok(report);
        }

        // Batch query for flow content (single query instead of N queries)
        let cron_flows = self
            .storage
            .get_deployed_flows_content(&cron_flow_names)
            .await?;

        // Clear existing jobs by removing each tracked job
        let job_ids: Vec<Uuid> = {
            let mut jobs = self.jobs.lock().await;
            let ids = jobs.values().copied().collect();
            jobs.clear();
            ids
        };

        let scheduler = self.scheduler.lock().await;
        for job_id in job_ids {
            if let Err(e) = scheduler.remove(&job_id).await {
                tracing::debug!(job_id = %job_id, error = %e, "Failed to remove job during sync");
            }
        }
        drop(scheduler); // Release lock before adding new jobs

        // Add jobs for each cron flow
        for (flow_name, content) in cron_flows {
            // Parse flow to extract cron expression
            let flow = match parse_string(&content, None) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(flow = %flow_name, error = %e, "Failed to parse flow");
                    report
                        .errors
                        .push(format!("{}: Failed to parse flow: {}", flow_name, e));
                    continue;
                }
            };

            let Some(cron_expr) = flow.cron else {
                let msg = "Flow has schedule.cron trigger but missing cron field";
                tracing::warn!(flow = %flow_name, msg);
                report.errors.push(format!("{}: {}", flow_name, msg));
                continue;
            };

            // Add job
            match self.add_job(&flow_name, &cron_expr).await {
                Ok(()) => {
                    report.scheduled.push(ScheduledFlow {
                        name: flow_name,
                        cron_expression: cron_expr,
                    });
                }
                Err(e) => {
                    tracing::warn!(flow = %flow_name, error = %e, "Failed to add job");
                    report.errors.push(format!("{}: {}", flow_name, e));
                }
            }
        }

        tracing::info!(
            scheduled = report.scheduled.len(),
            errors = report.errors.len(),
            "Cron full sync completed"
        );

        Ok(report)
    }

    /// Add or update schedule for a deployed flow.
    ///
    /// Called after Deploy/Enable/Rollback operations.
    /// Queries storage for flow content, checks for cron trigger, and schedules if present.
    ///
    /// # Performance
    ///
    /// ~0.1ms (single flow parse). Multiple flows can be scheduled in parallel.
    ///
    /// # Algorithm
    ///
    /// 1. Remove existing job for this flow (if any)
    /// 2. Query deployed version and content
    /// 3. Parse flow once to check trigger and extract cron expression
    /// 4. If has cron trigger, create and add job
    ///
    /// # Errors
    ///
    /// Returns error if storage query or scheduler operations fail.
    pub async fn add_schedule(&self, flow_name: &str) -> Result<()> {
        // Remove existing job if present (handles updates/redeploys)
        self.remove_job(flow_name).await?;

        // Check if flow is deployed
        let version = self.storage.get_deployed_version(flow_name).await?;
        let Some(version) = version else {
            tracing::debug!(flow = flow_name, "Flow not deployed");
            return Ok(());
        };

        // Get flow content
        let content = self
            .storage
            .get_flow_version_content(flow_name, &version)
            .await?
            .ok_or_else(|| {
                BeemFlowError::not_found("Flow version", format!("{}@{}", flow_name, version))
            })?;

        // Parse flow once - check trigger and extract cron expression
        let flow: Flow = parse_string(&content, None)
            .map_err(|e| BeemFlowError::validation(format!("Failed to parse flow: {}", e)))?;

        let has_cron = flow.on.includes("schedule.cron");

        if !has_cron {
            tracing::debug!(flow = flow_name, "Flow has no cron trigger");
            return Ok(());
        }

        // Extract cron expression
        let cron_expr = flow.cron.ok_or_else(|| {
            BeemFlowError::validation("Flow has schedule.cron trigger but missing cron field")
        })?;

        // Create and add job
        self.add_job(flow_name, &cron_expr).await?;

        tracing::info!(
            flow = flow_name,
            cron = %cron_expr,
            "Flow scheduled"
        );

        Ok(())
    }

    /// Remove schedule for a flow.
    ///
    /// Called after Disable operation.
    /// More efficient than add_schedule since it doesn't query storage.
    ///
    /// # Performance
    ///
    /// ~0.01ms (no storage query, just HashMap lookup + scheduler remove).
    ///
    /// # Errors
    ///
    /// Returns error if scheduler remove operation fails.
    pub async fn remove_schedule(&self, flow_name: &str) -> Result<()> {
        self.remove_job(flow_name).await?;

        tracing::info!(flow = flow_name, "Flow unscheduled");
        Ok(())
    }

    /// Add a job and track its UUID.
    ///
    /// Internal method used by `sync()` and `add_schedule()`.
    async fn add_job(&self, flow_name: &str, cron_expr: &str) -> Result<()> {
        // Create async job (Job::new_async validates the cron expression)
        let engine = self.engine.clone();
        let name = flow_name.to_string();

        let job = Job::new_async(cron_expr, move |uuid, _lock| {
            let engine = engine.clone();
            let name = name.clone();

            Box::pin(async move {
                tracing::info!(
                    job_id = %uuid,
                    flow = %name,
                    "Cron trigger: starting scheduled flow"
                );

                match engine.start(&name, HashMap::new(), false).await {
                    Ok(result) => {
                        tracing::info!(
                            job_id = %uuid,
                            flow = %name,
                            run_id = %result.run_id,
                            "Scheduled flow completed successfully"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            job_id = %uuid,
                            flow = %name,
                            error = %e,
                            "Scheduled flow execution failed"
                        );
                    }
                }
            })
        })
        .map_err(|e| {
            BeemFlowError::validation(format!("Invalid cron expression '{}': {}", cron_expr, e))
        })?;

        // Get job UUID before adding to scheduler
        let job_id = job.guid();

        // Add to scheduler
        let scheduler = self.scheduler.lock().await;
        scheduler
            .add(job)
            .await
            .map_err(|e| BeemFlowError::config(format!("Failed to add job to scheduler: {}", e)))?;
        drop(scheduler); // Release lock before updating jobs map

        // Track job UUID
        {
            let mut jobs = self.jobs.lock().await;
            jobs.insert(flow_name.to_string(), job_id);
        }

        tracing::debug!(
            flow = flow_name,
            job_id = %job_id,
            cron = %cron_expr,
            "Added cron job"
        );

        Ok(())
    }

    /// Remove job for a flow.
    ///
    /// Internal method used by `add_schedule()` and `remove_schedule()`.
    async fn remove_job(&self, flow_name: &str) -> Result<()> {
        let job_id = {
            let mut jobs = self.jobs.lock().await;
            jobs.remove(flow_name)
        };

        if let Some(job_id) = job_id {
            let scheduler = self.scheduler.lock().await;
            scheduler
                .remove(&job_id)
                .await
                .map_err(|e| BeemFlowError::config(format!("Failed to remove job: {}", e)))?;

            tracing::debug!(flow = flow_name, job_id = %job_id, "Removed cron job");
        }

        Ok(())
    }

    /// Gracefully shutdown the scheduler.
    ///
    /// Waits for all running jobs to complete before returning.
    /// After shutdown, the scheduler cannot be reused.
    ///
    /// # Errors
    ///
    /// Returns error if shutdown operation fails.
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("Shutting down cron scheduler");

        let mut scheduler = self.scheduler.lock().await;
        scheduler
            .shutdown()
            .await
            .map_err(|e| BeemFlowError::config(format!("Failed to shutdown scheduler: {}", e)))?;

        tracing::info!("Cron scheduler stopped");
        Ok(())
    }
}

/// Report from a full sync operation.
#[derive(Debug, Default, serde::Serialize)]
pub struct SyncReport {
    /// Flows successfully scheduled
    pub scheduled: Vec<ScheduledFlow>,
    /// Flows that failed to schedule (with error messages)
    pub errors: Vec<String>,
}

/// Information about a scheduled flow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScheduledFlow {
    pub name: String,
    pub cron_expression: String,
}

#[cfg(test)]
mod cron_test;
