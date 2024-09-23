use crate::client::intrinsic::has_sbom::{HasSBOM, HasSBOMIncludesInputSpec, HasSBOMInputSpec};
use crate::client::intrinsic::package::{IDorPkgInput, PackageQualifierInputSpec, PkgInputSpec};
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
            document_ref: value.document_ref.clone(),
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

impl From<&IDorPkgInput> for ingest_has_sbom::IDorPkgInput {
    fn from(value: &IDorPkgInput) -> Self {
        Self {
            package_type_id: value.package_type_id.clone(),
            package_namespace_id: value.package_namespace_id.clone(),
            package_name_id: value.package_name_id.clone(),
            package_version_id: value.package_version_id.clone(),
            package_input: value.package_input.as_ref().map(|inner| inner.into()),
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

impl From<&HasSBOMIncludesInputSpec> for ingest_has_sbom::HasSBOMIncludesInputSpec {
    fn from(value: &HasSBOMIncludesInputSpec) -> Self {
        Self {
            packages: value.packages.clone(),
            artifacts: value.artifacts.clone(),
            dependencies: value.dependencies.clone(),
            occurrences: value.occurrences.clone(),
        }
    }
}
