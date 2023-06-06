use async_trait::async_trait;
use async_nats::Client;

#[async_trait]
pub trait Emitter {
    async fn send(&self, subject: &str, data: Vec<u8>) -> Result<(), anyhow::Error>;
}

pub struct NatsEmitter {
    client: Client,
}

impl NatsEmitter {
    pub async fn new(url: &str) -> Result<Self, anyhow::Error> {
        let client = async_nats::connect(url).await?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Emitter for NatsEmitter {
    async fn send(&self, subject: &str, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.client.publish(subject.into(), data.into()).await.map_err(|e| anyhow::anyhow!(e))?;
        self.client.flush().await.map_err(|e| anyhow::anyhow!(e))
    }
}
