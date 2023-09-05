use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::str::FromStr;
use strum_macros::EnumString;

#[allow(clippy::module_inception)]
pub mod collector;
pub mod emitter;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub blob: Vec<u8>,
    pub r#type: DocumentType,
    pub format: FormatType,
    pub encoding: EncodingType,
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

#[derive(Serialize, Deserialize, EnumString, Debug)]
pub enum EncodingType {
    #[strum(ascii_case_insensitive)]
    BZIP2,
    #[strum(ascii_case_insensitive)]
    ZSTD,
    UNKNOWN,
}

impl From<Option<String>> for EncodingType {
    fn from(value: Option<String>) -> Self {
        match value {
            Some(str) => EncodingType::from_str(&str).unwrap_or(EncodingType::UNKNOWN),
            None => EncodingType::UNKNOWN,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SourceInformation {
    pub collector: String,
    pub source: String,
}
