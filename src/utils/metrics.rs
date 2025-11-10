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
        "moat_requests_total",
        "Total number of requests handled by Arxignis Moat"
    ).unwrap()
});

pub static RESPONSE_CODES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "moat_responses_total",
        "Responses grouped by status code by Arxignis Moat",
        &["status"]
    ).unwrap()
});

pub static REQUEST_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "moat_request_latency_seconds",
        "Request latency in seconds by Arxignis Moat",
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).unwrap()
});

pub static RESPONSE_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "moat_response_latency_seconds",
        "Response latency in seconds by Arxignis Moat",
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]
    ).unwrap()
});

pub static REQUESTS_BY_METHOD: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "moat_requests_by_method_total",
        "Number of requests by HTTP method by Arxignis Moat",
        &["method"]
    ).unwrap()
});

pub static REQUESTS_BY_VERSION: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "moat_requests_by_version_total",
        "Number of requests by HTTP versions by Arxignis Moat",
        &["version"]
    ).unwrap()
});

pub static ERROR_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "moat_errors_total",
        "Total number of errors by Arxignis Moat"
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
