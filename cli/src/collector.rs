use std::fs;

use anyhow::*;
use guac::collector::{Document, DocumentType, FormatType, SourceInformation, emitter::Emitter, emitter::NatsEmitter};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Collecting");

    //let nc = nats::connect("127.0.0.1:4222")?;
    let emitter = NatsEmitter::new("127.0.0.1:4222").await?;

    let path = "example/seedwing-java-example.bom";
    let content = fs::read(path)?;
    //let content = Vec::new();

    let document = Document {
        blob: content,
        r#type: DocumentType::UNKNOWN,
        format: FormatType::UNKNOWN,
        source_information: SourceInformation {
            collector: "FileCollector".into(),
            source: path.into(),
        },
    };

    //let payload = serde_json::json!(document);
    //println!("{}", payload);
    let bytes = serde_json::to_vec(&json!(document))?;

    //nc.publish("DOCUMENTS.collected", bytes)?;
    emitter.send("DOCUMENTS.collected", bytes).await?;

    Ok(())
}
