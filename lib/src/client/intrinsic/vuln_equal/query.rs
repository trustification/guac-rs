use crate::client::intrinsic::vuln_equal::query::query_vuln_equal::{
    allVulnEqualTree, AllVulnEqualTreeVulnerabilities, AllVulnEqualTreeVulnerabilitiesVulnerabilityIDs,
};
use crate::client::intrinsic::vuln_equal::{VulnEqual, VulnEqualSpec};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId, VulnerabilitySpec};
use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/vuln_equal/vuln_equal.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryVulnEqual;

impl From<&VulnEqualSpec> for query_vuln_equal::VulnEqualSpec {
    fn from(value: &VulnEqualSpec) -> Self {
        Self {
            id: value.id.clone(),
            vulnerabilities: value
                .vulnerabilities
                .as_ref()
                .map(|inner| inner.iter().map(|each| Some(each.into())).collect()),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&VulnerabilitySpec> for query_vuln_equal::VulnerabilitySpec {
    fn from(value: &VulnerabilitySpec) -> Self {
        Self {
            id: value.id.clone(),
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
            no_vuln: value.no_vuln,
        }
    }
}

impl From<&query_vuln_equal::allVulnEqualTree> for VulnEqual {
    fn from(value: &allVulnEqualTree) -> Self {
        Self {
            id: value.id.clone(),
            vulnerabilities: value.vulnerabilities.iter().map(|each| each.into()).collect(),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&query_vuln_equal::AllVulnEqualTreeVulnerabilities> for Vulnerability {
    fn from(value: &AllVulnEqualTreeVulnerabilities) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            vulnerability_ids: value.vulnerability_i_ds.iter().map(|each| each.into()).collect(),
        }
    }
}

impl From<&query_vuln_equal::AllVulnEqualTreeVulnerabilitiesVulnerabilityIDs> for VulnerabilityId {
    fn from(value: &AllVulnEqualTreeVulnerabilitiesVulnerabilityIDs) -> Self {
        Self {
            id: value.id.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}
