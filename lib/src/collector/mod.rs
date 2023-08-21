use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::Bytes;

#[allow(clippy::module_inception)]
pub mod collector;
pub mod emitter;

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    #[serde_as(as = "Bytes")]
    pub blob: Vec<u8>,
    pub r#type: DocumentType,
    pub format: FormatType,
    pub source_information: SourceInformation,
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
    pub collector: String,
    pub source: String,
}
