//! Run one provisioning job from a JSON request file and print its events, the
//! way the app's JNI layer does. For testing the engine against a real server:
//!
//! ```text
//! cargo run -p zero-provision --example run_job -- request.json
//! ```

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use zero_discovery::events::batching_sink;
use zero_provision::job::{run, Request};

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).expect("usage: run_job <request.json>");
    let text = std::fs::read_to_string(&path).expect("read the request file");
    let request: Request = serde_json::from_str(&text).expect("parse the request");
    let (sink, flusher) = batching_sink(Arc::new(|batch: String| println!("{batch}")));
    let reason = run(request, sink, CancellationToken::new()).await;
    let _ = flusher.await;
    eprintln!("end: {reason:?}");
}
