//use self::ingest_package::{PackageQualifierInputSpec, PkgInputSpec};
use crate::client::intrinsic::package::{PackageQualifierInputSpec, PkgInputSpec};
use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/package/package.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestPackage;

impl From<&PkgInputSpec> for ingest_package::PkgInputSpec {
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

impl From<&PackageQualifierInputSpec> for ingest_package::PackageQualifierInputSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}
