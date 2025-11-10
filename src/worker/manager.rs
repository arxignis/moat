use std::collections::HashMap;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Worker trait that all workers must implement
pub trait Worker: Send + Sync + 'static {
    /// Name of the worker
    fn name(&self) -> &str;

    /// Run the worker task
    fn run(&self, shutdown: watch::Receiver<bool>) -> JoinHandle<()>;
}

/// Worker configuration
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Worker name/identifier
    pub name: String,
    /// Schedule interval in seconds
    pub interval_secs: u64,
    /// Whether the worker is enabled
    pub enabled: bool,
}

/// Worker manager that manages multiple workers with their own schedules
pub struct WorkerManager {
    workers: HashMap<String, (WorkerConfig, JoinHandle<()>)>,
    shutdown_tx: watch::Sender<bool>,
}

impl WorkerManager {
    /// Create a new worker manager
    pub fn new() -> (Self, watch::Receiver<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        (
            Self {
                workers: HashMap::new(),
                shutdown_tx,
            },
            shutdown_rx,
        )
    }

    /// Register a worker with its configuration
    pub fn register_worker<W: Worker>(
        &mut self,
        config: WorkerConfig,
        worker: W,
    ) -> Result<(), String> {
        if !config.enabled {
            log::info!("Worker '{}' is disabled, skipping registration", config.name);
            return Ok(());
        }

        if self.workers.contains_key(&config.name) {
            return Err(format!("Worker '{}' is already registered", config.name));
        }

        let shutdown_rx = self.shutdown_tx.subscribe();
        let handle = worker.run(shutdown_rx);

        log::info!(
            "Registered worker '{}' with interval {}s",
            config.name,
            config.interval_secs
        );

        self.workers.insert(config.name.clone(), (config, handle));
        Ok(())
    }

    /// Get all worker handles for graceful shutdown
    pub fn get_handles(&self) -> Vec<(&str, &JoinHandle<()>)> {
        self.workers
            .iter()
            .map(|(name, (_, handle))| (name.as_str(), handle))
            .collect()
    }

    /// Shutdown all workers
    pub fn shutdown(&mut self) {
        log::info!("Shutting down {} workers...", self.workers.len());
        let _ = self.shutdown_tx.send(true);
    }

    /// Wait for all workers to complete
    pub async fn wait_for_all(&mut self) {
        let handles: Vec<_> = self.workers.drain().map(|(_, (_, handle))| handle).collect();

        for handle in handles {
            if let Err(e) = handle.await {
                log::error!("Worker task join error: {}", e);
            }
        }

        log::info!("All workers stopped");
    }
}

impl Default for WorkerManager {
    fn default() -> Self {
        Self::new().0
    }
}

