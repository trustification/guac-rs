use crate::client::intrinsic::vuln_metadata::query::query_vulnerability_metadata::QueryVulnerabilityMetadataVulnerabilityMetadata;
use crate::client::intrinsic::vuln_metadata::{
    Comparator, VulnerabilityMetadata, VulnerabilityMetadataSpec, VulnerabilityScoreType,
};
use crate::client::intrinsic::vulnerability::VulnerabilitySpec;
use chrono::Utc;
use graphql_client::GraphQLQuery;

type Time = chrono::DateTime<Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/vuln_metadata/vuln_metadata.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryVulnerabilityMetadata;

impl From<&VulnerabilityMetadataSpec> for query_vulnerability_metadata::VulnerabilityMetadataSpec {
    fn from(value: &VulnerabilityMetadataSpec) -> Self {
        Self {
            id: value.id.clone(),
            vulnerability: value.vulnerability.as_ref().map(|inner| inner.into()),
            score_type: value.score_type.as_ref().map(|inner| inner.into()),
            score_value: value.score_value.clone(),
            comparator: value.comparator.as_ref().map(|inner| inner.into()),
            timestamp: value.timestamp,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&VulnerabilityScoreType> for query_vulnerability_metadata::VulnerabilityScoreType {
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

impl From<&Comparator> for query_vulnerability_metadata::Comparator {
    fn from(value: &Comparator) -> Self {
        match value {
            Comparator::Greater => Self::GREATER,
            Comparator::Equal => Self::EQUAL,
            Comparator::Less => Self::LESS,
            Comparator::GreaterEqual => Self::GREATER_EQUAL,
            Comparator::LessEqual => Self::LESS_EQUAL,
        }
    }
}

impl From<&VulnerabilitySpec> for query_vulnerability_metadata::VulnerabilitySpec {
    fn from(value: &VulnerabilitySpec) -> Self {
        Self {
            id: value.id.clone(),
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
            no_vuln: value.no_vuln,
        }
    }
}

impl From<&query_vulnerability_metadata::QueryVulnerabilityMetadataVulnerabilityMetadata>
    for VulnerabilityMetadata
{
    fn from(value: &QueryVulnerabilityMetadataVulnerabilityMetadata) -> Self {
        Self {
            id: value.id.clone(),
            score_type: (&value.score_type).into(),
            score_value: value.score_value,
            timestamp: value.timestamp,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&query_vulnerability_metadata::VulnerabilityScoreType> for VulnerabilityScoreType {
    fn from(value: &query_vulnerability_metadata::VulnerabilityScoreType) -> Self {
        match value {
            query_vulnerability_metadata::VulnerabilityScoreType::CVSSv2 => Self::CVSSv2,
            query_vulnerability_metadata::VulnerabilityScoreType::CVSSv3 => Self::CVSSv3,
            query_vulnerability_metadata::VulnerabilityScoreType::EPSSv1 => Self::EPSSv1,
            query_vulnerability_metadata::VulnerabilityScoreType::EPSSv2 => Self::EPSSv2,
            query_vulnerability_metadata::VulnerabilityScoreType::CVSSv31 => Self::CVSSv31,
            query_vulnerability_metadata::VulnerabilityScoreType::CVSSv4 => Self::CVSSv4,
            query_vulnerability_metadata::VulnerabilityScoreType::OWASP => Self::OWASP,
            query_vulnerability_metadata::VulnerabilityScoreType::SSVC => Self::SSVC,
            query_vulnerability_metadata::VulnerabilityScoreType::Other(other) => {
                Self::Other(other.clone())
            }
        }
    }
}
