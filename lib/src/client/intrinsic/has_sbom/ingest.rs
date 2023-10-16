use crate::client::intrinsic::has_sbom::{HasSBOM, HasSBOMInputSpec};
use crate::client::intrinsic::package::{PackageQualifierInputSpec, PkgInputSpec};
use crate::client::intrinsic::PackageOrArtifactInput;
use chrono::Utc;
use graphql_client::GraphQLQuery;

type Time = chrono::DateTime<Utc>;
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/has_sbom/has_sbom.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestHasSBOM;

impl From<&PackageOrArtifactInput> for ingest_has_sbom::PackageOrArtifactInput {
    fn from(value: &PackageOrArtifactInput) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None,
        }
    }
}

impl From<&HasSBOMInputSpec> for ingest_has_sbom::HasSBOMInputSpec {
    fn from(value: &HasSBOMInputSpec) -> Self {
        Self {
            uri: value.uri.clone(),
            algorithm: value.algorithm.clone(),
            digest: value.digest.clone(),
            download_location: value.download_location.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            known_since: value.known_since,
        }
    }
}

impl From<&PkgInputSpec> for ingest_has_sbom::PkgInputSpec {
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

impl From<&PackageQualifierInputSpec> for ingest_has_sbom::PackageQualifierInputSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}
