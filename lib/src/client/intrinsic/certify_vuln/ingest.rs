use chrono::Utc;

use graphql_client::GraphQLQuery;

use crate::client::intrinsic::certify_vuln::ScanMetadataInput;
use crate::client::intrinsic::package::{IDorPkgInput, PackageQualifierInputSpec, PkgInputSpec};
use crate::client::intrinsic::vulnerability::{IDorVulnerabilityInput, VulnerabilityInputSpec};

type Time = chrono::DateTime<Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_vuln/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestCertifyVuln;

impl From<&PkgInputSpec> for ingest_certify_vuln::PkgInputSpec {
    fn from(value: &PkgInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            namespace: value.namespace.clone(),
            name: value.name.clone(),
            version: value.version.clone(),
            qualifiers: value
                .qualifiers
                .clone()
                .map(|inner| inner.iter().map(|each| each.into()).collect()),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&VulnerabilityInputSpec> for ingest_certify_vuln::VulnerabilityInputSpec {
    fn from(value: &VulnerabilityInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

impl From<&ScanMetadataInput> for ingest_certify_vuln::ScanMetadataInput {
    fn from(value: &ScanMetadataInput) -> Self {
        Self {
            time_scanned: value.time_scanned,
            db_uri: value.db_uri.clone(),
            db_version: value.db_version.clone(),
            scanner_uri: value.scanner_uri.clone(),
            scanner_version: value.scanner_version.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            document_ref: value.document_ref.clone(),
        }
    }
}

impl From<&PackageQualifierInputSpec> for ingest_certify_vuln::PackageQualifierInputSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&IDorPkgInput> for ingest_certify_vuln::IDorPkgInput {
    fn from(value: &IDorPkgInput) -> Self {
        Self {
            package_type_id: value.package_type_id.clone(),
            package_namespace_id: value.package_namespace_id.clone(),
            package_name_id: value.package_name_id.clone(),
            package_version_id: value.package_version_id.clone(),
            package_input: value.package_input.as_ref().map(|pkg| pkg.into()),
        }
    }
}

impl From<&IDorVulnerabilityInput> for ingest_certify_vuln::IDorVulnerabilityInput {
    fn from(vuln: &IDorVulnerabilityInput) -> Self {
        Self {
            vulnerability_input: vuln.vulnerability_input.as_ref().map(|vuln| vuln.into()),
            vulnerability_node_id: vuln.vulnerability_node_id.clone(),
            vulnerability_type_id: vuln.vulnerability_type_id.clone(),
        }
    }
}
