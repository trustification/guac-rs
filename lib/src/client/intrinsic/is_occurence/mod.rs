use crate::client::intrinsic::artifact::ArtifactSpec;
use crate::client::intrinsic::PackageOrSourceSpec;
use crate::client::Id;

#[derive(Default, Debug, Clone)]
pub struct IsOccurrenceSpec {
    pub id: Option<Id>,
    pub subject: Option<PackageOrSourceSpec>,
    pub artifact: Option<ArtifactSpec>,
    pub justification: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,
    pub document_ref: Option<String>,
}
