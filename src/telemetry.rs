//! Telemetry module for BeemFlow
//!
//! Provides Prometheus metrics and OpenTelemetry tracing support.

use crate::{BeemFlowError, Result, config::TracingConfig};
use once_cell::sync::Lazy;
use prometheus::{
    CounterVec, Encoder, HistogramOpts, HistogramVec, TextEncoder, register_counter_vec,
    register_histogram_vec,
};

/// HTTP requests total counter
static HTTP_REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "beemflow_http_requests_total",
        "Total number of HTTP requests received",
        &["handler", "method", "code"]
    )
    .expect("Failed to register beemflow_http_requests_total metric")
});

/// HTTP request duration histogram
static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "beemflow_http_request_duration_seconds",
            "Duration of HTTP requests in seconds"
        ),
        &["handler", "method"]
    )
    .expect("Failed to register beemflow_http_request_duration_seconds metric")
});

/// Flow execution counter
static FLOW_EXECUTIONS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "beemflow_flow_executions_total",
        "Total number of flow executions",
        &["flow", "status"]
    )
    .expect("Failed to register beemflow_flow_executions_total metric")
});

/// Flow execution duration histogram
static FLOW_EXECUTION_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "beemflow_flow_execution_duration_seconds",
            "Duration of flow executions in seconds"
        ),
        &["flow"]
    )
    .expect("Failed to register beemflow_flow_execution_duration_seconds metric")
});

/// Step execution counter
static STEP_EXECUTIONS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "beemflow_step_executions_total",
        "Total number of step executions",
        &["flow", "step", "status"]
    )
    .expect("Failed to register beemflow_step_executions_total metric")
});

/// Initialize telemetry based on configuration
///
/// Currently sets up Prometheus metrics (which are automatically registered via once_cell).
/// OpenTelemetry tracing can be added in the future as needed.
pub fn init(config: Option<&TracingConfig>) -> Result<()> {
    let service_name = config
        .and_then(|c| c.service_name.as_deref())
        .unwrap_or("beemflow");

    // Prometheus metrics are automatically registered via once_cell
    // This init function is a placeholder for future OpenTelemetry integration
    tracing::info!("Telemetry initialized for service: {}", service_name);

    // TODO: Add OpenTelemetry tracing support when needed
    // The OpenTelemetry 0.31.0 API has significant changes from earlier versions
    // For now, we focus on Prometheus metrics which are production-ready

    Ok(())
}

/// Record HTTP request metric
pub fn record_http_request(handler: &str, method: &str, status_code: u16) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[handler, method, &status_code.to_string()])
        .inc();
}

/// Record HTTP request duration
pub fn record_http_duration(handler: &str, method: &str, duration_secs: f64) {
    HTTP_REQUEST_DURATION
        .with_label_values(&[handler, method])
        .observe(duration_secs);
}

/// Record flow execution
pub fn record_flow_execution(flow_name: &str, status: &str) {
    FLOW_EXECUTIONS_TOTAL
        .with_label_values(&[flow_name, status])
        .inc();
}

/// Record flow execution duration
pub fn record_flow_duration(flow_name: &str, duration_secs: f64) {
    FLOW_EXECUTION_DURATION
        .with_label_values(&[flow_name])
        .observe(duration_secs);
}

/// Record step execution
pub fn record_step_execution(flow_name: &str, step_name: &str, status: &str) {
    STEP_EXECUTIONS_TOTAL
        .with_label_values(&[flow_name, step_name, status])
        .inc();
}

/// Get Prometheus metrics in text format
pub fn get_metrics() -> Result<String> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| BeemFlowError::config(format!("Failed to encode metrics: {}", e)))?;

    String::from_utf8(buffer)
        .map_err(|e| BeemFlowError::config(format!("Failed to convert metrics to UTF-8: {}", e)))
}

/// HTTP middleware for recording metrics
///
/// This is a simplified version - in production, this would be integrated
/// with Axum middleware for automatic metric collection.
pub struct MetricsMiddleware {
    handler_name: String,
}

impl MetricsMiddleware {
    pub fn new(handler_name: impl Into<String>) -> Self {
        Self {
            handler_name: handler_name.into(),
        }
    }

    /// Record request start time
    pub fn start(&self) -> std::time::Instant {
        std::time::Instant::now()
    }

    /// Record request completion
    pub fn finish(&self, start: std::time::Instant, method: &str, status_code: u16) {
        let duration = start.elapsed();
        let duration_secs = duration.as_secs_f64();

        record_http_request(&self.handler_name, method, status_code);
        record_http_duration(&self.handler_name, method, duration_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_metrics() {
        // Record some test metrics
        record_http_request("test_handler", "GET", 200);
        record_http_duration("test_handler", "GET", 0.123);
        record_flow_execution("test_flow", "success");
        record_flow_duration("test_flow", 1.5);
        record_step_execution("test_flow", "step1", "success");

        // Get metrics
        let metrics = get_metrics().unwrap();

        // Verify metrics are present
        assert!(metrics.contains("beemflow_http_requests_total"));
        assert!(metrics.contains("beemflow_http_request_duration_seconds"));
        assert!(metrics.contains("beemflow_flow_executions_total"));
        assert!(metrics.contains("beemflow_flow_execution_duration_seconds"));
        assert!(metrics.contains("beemflow_step_executions_total"));
    }

    #[test]
    fn test_metrics_middleware() {
        let middleware = MetricsMiddleware::new("test_endpoint");
        let start = middleware.start();

        // Simulate some work
        std::thread::sleep(std::time::Duration::from_millis(10));

        middleware.finish(start, "POST", 201);

        // Verify metrics were recorded
        let metrics = get_metrics().unwrap();
        assert!(metrics.contains("beemflow_http_requests_total"));
    }
}
