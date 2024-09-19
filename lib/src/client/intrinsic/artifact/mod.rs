use crate::client::Id;

#[derive(Default, Debug, Clone)]
pub struct ArtifactSpec {
    pub id: Option<Id>,
    pub algorithm: Option<String>,
    pub digest: Option<String>,
}
