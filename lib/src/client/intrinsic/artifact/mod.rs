use crate::client::Id;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone)]
pub struct ArtifactSpec {
    pub id: Option<Id>,
    pub algorithm: Option<String>,
    pub digest: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Artifact {
    pub id: Id,
    pub algorithm: String,
    pub digest: String,
}
