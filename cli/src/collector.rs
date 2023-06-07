use anyhow::*;
use guac::collector::{emitter::NatsEmitter, collector::{FileCollector, Collector}};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Collecting ...");

    let emitter = NatsEmitter::new("127.0.0.1:4222").await?;

    let collector = FileCollector {
        path: "example/seedwing-java-example.bom".to_string(),
    };

    collector.run(emitter).await?;

    Ok(())
}
