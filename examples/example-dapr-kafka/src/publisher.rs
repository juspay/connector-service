use anyhow::{Context, Result};
use reqwest;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;

// Define a simple event struct to publish
#[derive(Debug, Serialize, Deserialize)]
struct PaymentEvent {
    payment_id: String,
    amount: f64,
    currency: String,
    status: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments for custom payment data
    let args: Vec<String> = env::args().collect();
    
    // Default values
    let mut payment_id = "test_payment_123".to_string();
    let mut amount = 100.0;
    let mut currency = "USD".to_string();
    let mut status = "completed".to_string();
    
    // Check for custom payment_id
    if args.len() > 1 {
        payment_id = args[1].clone();
    }
    
    // Check for custom amount
    if args.len() > 2 {
        amount = args[2].parse::<f64>().unwrap_or(100.0);
    }
    
    // Check for custom currency
    if args.len() > 3 {
        currency = args[3].clone();
    }
    
    // Check for custom status
    if args.len() > 4 {
        status = args[4].clone();
    }
    
    // Create a payment event with the provided or default values
    let event = PaymentEvent {
        payment_id,
        amount,
        currency,
        status,
    };
    
    println!("Connecting to Dapr sidecar...");
    // When running with Dapr CLI, use the automatically assigned sidecar HTTP port
    // The port is passed via environment variable DAPR_HTTP_PORT
    let dapr_port = std::env::var("DAPR_HTTP_PORT").unwrap_or_else(|_| "3500".to_string());
    let dapr_url = format!("http://localhost:{}", dapr_port);
    println!("Connecting to Dapr sidecar at: {}", dapr_url);
    
    // Create HTTP client
    let client = reqwest::Client::new();

    println!("Publishing payment event to Kafka through Dapr...");
    // Convert event to JSON string for publishing
    let event_json = serde_json::to_string(&event)?;
    
    // Publish event to Kafka through Dapr's HTTP API
    let url = format!("{}/v1.0/publish/kafka-pubsub/payment-events", dapr_url);
    println!("Sending HTTP request to: {}", url);
    
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(event_json.clone())
        .send()
        .await
        .context("Failed to send HTTP request to Dapr sidecar")?;
    
    let status = response.status();
    let response_text = response.text().await?;
    
    if status.is_success() {
        println!("Successfully published payment event to Kafka");
        println!("Response: {}", response_text);
        println!("Event details: {}", serde_json::to_string_pretty(&event)?);
    } else {
        println!("Failed to publish event. Status: {}, Response: {}", status, response_text);
        std::process::exit(1);
    }
    
    // Wait a moment before exiting to ensure message is processed
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    Ok(())
}
