use std::fs;

use anyhow::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Collecting");

    let nc = nats::connect("127.0.0.1:4222")?;

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

    nc.publish("DOCUMENTS.collected", bytes)?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    blob: Vec<u8>,
    r#type: DocumentType,
    format: FormatType,
    source_information: SourceInformation,
}

#[derive(Serialize, Deserialize)]
pub enum DocumentType {
    SLSA,
    ITE6,
    ITE6VUL,
    DSSE,
    SPDX,
    JsonLines,
    SCORECARD,
    CyclonDX,
    DepsDev,
    UNKNOWN,
}

#[derive(Serialize, Deserialize)]
pub enum FormatType {
    JSON,
    JsonLines,
    XML,
    UNKNOWN,
}

#[derive(Serialize, Deserialize)]
pub struct SourceInformation {
    collector: String,
    source: String,
}
