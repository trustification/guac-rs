use std::fs;

use async_trait::async_trait;

use super::{Document, DocumentType, FormatType, SourceInformation, emitter::Emitter};

#[async_trait]
pub trait Collector {
    async fn run<E: Emitter + Send + Sync>(&self, emitter: E) -> Result<(), anyhow::Error>;
}


pub struct FileCollector {
    pub path: String,
}

#[async_trait]
impl Collector for FileCollector {
    async fn run<E: Emitter + Send + Sync>(&self, emitter: E) -> Result<(), anyhow::Error> {
        let content = fs::read(self.path.clone())?;

        let document = Document {
            blob: content,
            r#type: DocumentType::UNKNOWN,
            format: FormatType::UNKNOWN,
            source_information: SourceInformation {
                collector: "FileCollector".into(),
                source: self.path.clone(),
            },
        };

        emitter.publish(document).await?;
        Ok(())
    }
}
