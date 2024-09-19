use crate::client::intrinsic::vuln_equal::VulnEqualInputSpec;
use crate::client::intrinsic::vulnerability::{IDorVulnerabilityInput, VulnerabilityInputSpec};
use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/vuln_equal/vuln_equal.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestVulnEqual;

impl From<&VulnerabilityInputSpec> for ingest_vuln_equal::VulnerabilityInputSpec {
    fn from(value: &VulnerabilityInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

impl From<&VulnEqualInputSpec> for ingest_vuln_equal::VulnEqualInputSpec {
    fn from(value: &VulnEqualInputSpec) -> Self {
        Self {
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            document_ref: value.document_ref.clone(),
        }
    }
}

impl From<&IDorVulnerabilityInput> for ingest_vuln_equal::IDorVulnerabilityInput {
    fn from(vuln: &IDorVulnerabilityInput) -> Self {
        Self {
            vulnerability_input: vuln.vulnerability_input.as_ref().map(|vuln| vuln.into()),
            vulnerability_node_id: vuln.vulnerability_node_id.clone(),
            vulnerability_type_id: vuln.vulnerability_type_id.clone(),
        }
    }
}
