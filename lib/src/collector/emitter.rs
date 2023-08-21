use async_nats::Client;
use async_trait::async_trait;
use serde_json::json;

use super::Document;

const SUBJECT_COLLECTED: &str = "DOCUMENTS.collected";

#[async_trait]
pub trait Emitter {
    async fn send(&self, subject: &str, data: Vec<u8>) -> Result<(), anyhow::Error>;

    async fn publish(&self, document: Document) -> Result<(), anyhow::Error> {
        log::info!("Serializing");

        let bytes = serde_json::to_vec(&json!(document))?;

        //self.send(SUBJECT_COLLECTED, bytes).await
        log::info!("Sending {:?}", bytes.len());
        Ok(())
    }
}

pub struct NatsEmitter {
    client: Client,
}

impl NatsEmitter {
    pub async fn new(url: &str) -> Result<Self, anyhow::Error> {
        let client = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .connect(url)
            .await?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Emitter for NatsEmitter {
    async fn send(&self, subject: &str, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.client
            .publish(subject.into(), data.into())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        self.client.flush().await.map_err(|e| anyhow::anyhow!(e))
    }
}
