//! Load testing tool for Keycloak Rust
//!
//! Tests server performance under load to validate v1.0 success criteria:
//! - Support 10,000+ concurrent sessions
//! - Sub-100ms token endpoint latency (p99)
//! - Memory usage under 256MB idle

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use hdrhistogram::Histogram;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Mutex;

/// Load testing tool for Keycloak Rust
#[derive(Parser, Debug)]
#[command(name = "load-test")]
#[command(about = "Load testing tool for Keycloak Rust server")]
struct Args {
    /// Server URL
    #[arg(short, long, default_value = "http://localhost:3000")]
    server: String,

    /// Realm to test against
    #[arg(short, long, default_value = "test")]
    realm: String,

    /// Client ID for testing
    #[arg(short, long, default_value = "test-client")]
    client_id: String,

    /// Client secret
    #[arg(long, default_value = "test-secret")]
    client_secret: String,

    /// Number of concurrent workers
    #[arg(short, long, default_value = "100")]
    workers: usize,

    /// Total number of requests to make
    #[arg(short, long, default_value = "10000")]
    requests: u64,

    /// Test type: token, discovery, jwks, introspect
    #[arg(short, long, default_value = "token")]
    test_type: String,

    /// Duration in seconds (alternative to request count)
    #[arg(short, long)]
    duration: Option<u64>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Token response from server
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    expires_in: u64,
}

/// Introspection response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IntrospectionResponse {
    active: bool,
}

/// Test results
#[derive(Debug)]
struct TestResults {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    total_duration: Duration,
    latency_histogram: Histogram<u64>,
}

impl TestResults {
    fn new() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            total_duration: Duration::ZERO,
            latency_histogram: Histogram::new(3).unwrap(),
        }
    }

    fn print_report(&self) {
        println!("\n═══════════════════════════════════════════════════════════════");
        println!("                     LOAD TEST RESULTS");
        println!("═══════════════════════════════════════════════════════════════\n");

        let rps = if self.total_duration.as_secs_f64() > 0.0 {
            self.total_requests as f64 / self.total_duration.as_secs_f64()
        } else {
            0.0
        };

        println!("Summary:");
        println!("  Total requests:      {}", self.total_requests);
        println!("  Successful:          {} ({:.1}%)",
            self.successful_requests,
            (self.successful_requests as f64 / self.total_requests as f64) * 100.0
        );
        println!("  Failed:              {} ({:.1}%)",
            self.failed_requests,
            (self.failed_requests as f64 / self.total_requests as f64) * 100.0
        );
        println!("  Total duration:      {:.2}s", self.total_duration.as_secs_f64());
        println!("  Requests/second:     {:.2}", rps);

        println!("\nLatency (milliseconds):");
        println!("  Min:                 {:.2}ms", self.latency_histogram.min() as f64 / 1000.0);
        println!("  Mean:                {:.2}ms", self.latency_histogram.mean() / 1000.0);
        println!("  p50 (median):        {:.2}ms", self.latency_histogram.value_at_quantile(0.50) as f64 / 1000.0);
        println!("  p90:                 {:.2}ms", self.latency_histogram.value_at_quantile(0.90) as f64 / 1000.0);
        println!("  p95:                 {:.2}ms", self.latency_histogram.value_at_quantile(0.95) as f64 / 1000.0);
        println!("  p99:                 {:.2}ms", self.latency_histogram.value_at_quantile(0.99) as f64 / 1000.0);
        println!("  Max:                 {:.2}ms", self.latency_histogram.max() as f64 / 1000.0);

        // v1.0 criteria check
        println!("\n═══════════════════════════════════════════════════════════════");
        println!("                   V1.0 CRITERIA CHECK");
        println!("═══════════════════════════════════════════════════════════════\n");

        let p99_ms = self.latency_histogram.value_at_quantile(0.99) as f64 / 1000.0;
        let p99_pass = p99_ms < 100.0;

        println!("  Token endpoint p99 < 100ms: {} ({:.2}ms)",
            if p99_pass { "✓ PASS" } else { "✗ FAIL" },
            p99_ms
        );

        let success_rate = self.successful_requests as f64 / self.total_requests as f64;
        let reliability_pass = success_rate >= 0.999;

        println!("  Reliability >= 99.9%:       {} ({:.2}%)",
            if reliability_pass { "✓ PASS" } else { "✗ FAIL" },
            success_rate * 100.0
        );

        println!("\n═══════════════════════════════════════════════════════════════\n");
    }
}

/// Run token endpoint load test
async fn run_token_test(
    client: &Client,
    args: &Args,
    counter: Arc<AtomicU64>,
    target: u64,
    results: Arc<Mutex<TestResults>>,
) {
    let url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        args.server, args.realm
    );

    loop {
        let current = counter.fetch_add(1, Ordering::SeqCst);
        if current >= target {
            break;
        }

        let start = Instant::now();

        let response = client
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &args.client_id),
                ("client_secret", &args.client_secret),
            ])
            .send()
            .await;

        let latency = start.elapsed();
        let latency_us = latency.as_micros() as u64;

        let mut results = results.lock().await;
        results.total_requests += 1;
        let _ = results.latency_histogram.record(latency_us);

        match response {
            Ok(resp) if resp.status().is_success() => {
                results.successful_requests += 1;
            }
            _ => {
                results.failed_requests += 1;
            }
        }
    }
}

/// Run discovery endpoint load test
async fn run_discovery_test(
    client: &Client,
    args: &Args,
    counter: Arc<AtomicU64>,
    target: u64,
    results: Arc<Mutex<TestResults>>,
) {
    let url = format!(
        "{}/realms/{}/.well-known/openid-configuration",
        args.server, args.realm
    );

    loop {
        let current = counter.fetch_add(1, Ordering::SeqCst);
        if current >= target {
            break;
        }

        let start = Instant::now();
        let response = client.get(&url).send().await;
        let latency = start.elapsed();
        let latency_us = latency.as_micros() as u64;

        let mut results = results.lock().await;
        results.total_requests += 1;
        let _ = results.latency_histogram.record(latency_us);

        match response {
            Ok(resp) if resp.status().is_success() => {
                results.successful_requests += 1;
            }
            _ => {
                results.failed_requests += 1;
            }
        }
    }
}

/// Run JWKS endpoint load test
async fn run_jwks_test(
    client: &Client,
    args: &Args,
    counter: Arc<AtomicU64>,
    target: u64,
    results: Arc<Mutex<TestResults>>,
) {
    let url = format!(
        "{}/realms/{}/protocol/openid-connect/certs",
        args.server, args.realm
    );

    loop {
        let current = counter.fetch_add(1, Ordering::SeqCst);
        if current >= target {
            break;
        }

        let start = Instant::now();
        let response = client.get(&url).send().await;
        let latency = start.elapsed();
        let latency_us = latency.as_micros() as u64;

        let mut results = results.lock().await;
        results.total_requests += 1;
        let _ = results.latency_histogram.record(latency_us);

        match response {
            Ok(resp) if resp.status().is_success() => {
                results.successful_requests += 1;
            }
            _ => {
                results.failed_requests += 1;
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("Keycloak Rust Load Test");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Server:          {}", args.server);
    println!("  Realm:           {}", args.realm);
    println!("  Test type:       {}", args.test_type);
    println!("  Workers:         {}", args.workers);
    println!("  Target requests: {}", args.requests);
    println!("═══════════════════════════════════════════════════════════════\n");

    // Create HTTP client with connection pooling
    let client = Client::builder()
        .pool_max_idle_per_host(args.workers)
        .timeout(Duration::from_secs(30))
        .build()?;

    let counter = Arc::new(AtomicU64::new(0));
    let results = Arc::new(Mutex::new(TestResults::new()));

    // Progress bar
    let pb = ProgressBar::new(args.requests);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")?
            .progress_chars("#>-"),
    );

    let start_time = Instant::now();

    // Spawn workers
    let mut handles = vec![];
    for _ in 0..args.workers {
        let client = client.clone();
        let args_clone = Args {
            server: args.server.clone(),
            realm: args.realm.clone(),
            client_id: args.client_id.clone(),
            client_secret: args.client_secret.clone(),
            workers: args.workers,
            requests: args.requests,
            test_type: args.test_type.clone(),
            duration: args.duration,
            verbose: args.verbose,
        };
        let counter = counter.clone();
        let results = results.clone();
        let _pb = pb.clone();

        let handle = tokio::spawn(async move {
            match args_clone.test_type.as_str() {
                "token" => {
                    run_token_test(&client, &args_clone, counter, args_clone.requests, results).await;
                }
                "discovery" => {
                    run_discovery_test(&client, &args_clone, counter, args_clone.requests, results).await;
                }
                "jwks" => {
                    run_jwks_test(&client, &args_clone, counter, args_clone.requests, results).await;
                }
                _ => {
                    eprintln!("Unknown test type: {}", args_clone.test_type);
                }
            }
        });

        handles.push(handle);
    }

    // Update progress bar
    let pb_clone = pb.clone();
    let counter_clone = counter.clone();
    let target = args.requests;
    tokio::spawn(async move {
        loop {
            let current = counter_clone.load(Ordering::SeqCst);
            pb_clone.set_position(current.min(target));
            if current >= target {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    // Wait for all workers
    for handle in handles {
        let _ = handle.await;
    }

    pb.finish_with_message("done");

    let total_duration = start_time.elapsed();

    // Update final results
    {
        let mut results = results.lock().await;
        results.total_duration = total_duration;
    }

    // Print results
    let results = results.lock().await;
    results.print_report();

    Ok(())
}
