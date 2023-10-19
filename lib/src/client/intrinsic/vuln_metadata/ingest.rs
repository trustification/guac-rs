use crate::client::intrinsic::vuln_metadata::{
    VulnerabilityMetadataInputSpec, VulnerabilityScoreType,
};
use crate::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use chrono::Utc;
use graphql_client::GraphQLQuery;

type Time = chrono::DateTime<Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/vuln_metadata/vuln_metadata.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestVulnerabilityMetadata;

impl From<&VulnerabilityInputSpec> for ingest_vulnerability_metadata::VulnerabilityInputSpec {
    fn from(value: &VulnerabilityInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

impl From<&VulnerabilityMetadataInputSpec>
    for ingest_vulnerability_metadata::VulnerabilityMetadataInputSpec
{
    fn from(value: &VulnerabilityMetadataInputSpec) -> Self {
        Self {
            score_type: (&value.score_type).into(),
            score_value: value.score_value,
            timestamp: value.timestamp,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&VulnerabilityScoreType> for ingest_vulnerability_metadata::VulnerabilityScoreType {
    fn from(value: &VulnerabilityScoreType) -> Self {
        match value {
            VulnerabilityScoreType::CVSSv2 => Self::CVSSv2,
            VulnerabilityScoreType::CVSSv3 => Self::CVSSv3,
            VulnerabilityScoreType::CVSSv31 => Self::CVSSv31,
            VulnerabilityScoreType::CVSSv4 => Self::CVSSv4,
            VulnerabilityScoreType::EPSSv1 => Self::CVSSv4,
            VulnerabilityScoreType::EPSSv2 => Self::EPSSv2,
            VulnerabilityScoreType::OWASP => Self::OWASP,
            VulnerabilityScoreType::SSVC => Self::SSVC,
            VulnerabilityScoreType::Other(inner) => Self::Other(inner.clone()),
        }
    }
}
