use pingora_http::Version;
use prometheus::{register_histogram, register_int_counter, register_int_counter_vec, Histogram, IntCounter, IntCounterVec};
use std::time::Duration;
use once_cell::sync::Lazy;

pub struct MetricTypes {
    pub method: String,
    pub code: String,
    pub latency: Duration,
    pub version: Version,
}

pub static REQUEST_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "synapse_requests_total",
        "Total number of requests handled by Gen0Sec Synapse"
    ).unwrap()
});

pub static RESPONSE_CODES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "synapse_responses_total",
        "Responses grouped by status code by Gen0Sec Synapse",
        &["status"]
    ).unwrap()
});

pub static REQUEST_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "synapse_request_latency_seconds",
        "Request latency in seconds by Gen0Sec Synapse",
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).unwrap()
});

pub static RESPONSE_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "synapse_response_latency_seconds",
        "Response latency in seconds by Gen0Sec Synapse",
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]
    ).unwrap()
});

pub static REQUESTS_BY_METHOD: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "synapse_requests_by_method_total",
        "Number of requests by HTTP method by Gen0Sec Synapse",
        &["method"]
    ).unwrap()
});

pub static REQUESTS_BY_VERSION: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "synapse_requests_by_version_total",
        "Number of requests by HTTP versions by Gen0Sec Synapse",
        &["version"]
    ).unwrap()
});

pub static ERROR_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "synapse_errors_total",
        "Total number of errors by Gen0Sec Synapse"
    ).unwrap()
});

pub fn calc_metrics(metric_types: &MetricTypes) {
    REQUEST_COUNT.inc();
    let timer = REQUEST_LATENCY.start_timer();
    timer.observe_duration();

    let version_str = match &metric_types.version {
        &Version::HTTP_11 => "HTTP/1.1",
        &Version::HTTP_2 => "HTTP/2.0",
        &Version::HTTP_3 => "HTTP/3.0",
        &Version::HTTP_10 => "HTTP/1.0",
        _ => "Unknown",
    };
    REQUESTS_BY_VERSION.with_label_values(&[&version_str]).inc();
    RESPONSE_CODES.with_label_values(&[&metric_types.code.to_string()]).inc();
    REQUESTS_BY_METHOD.with_label_values(&[&metric_types.method]).inc();
    RESPONSE_LATENCY.observe(metric_types.latency.as_secs_f64());
}
