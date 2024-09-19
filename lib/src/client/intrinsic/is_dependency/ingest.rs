use crate::client::intrinsic::is_dependency::{DependencyType, IsDependencyInputSpec};
use crate::client::intrinsic::package::{IDorPkgInput, PackageQualifierInputSpec, PkgInputSpec};
use crate::client::intrinsic::{MatchFlags, PkgMatchType};
use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/is_dependency/is_dependency.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestDependency;

impl From<&PkgInputSpec> for ingest_dependency::PkgInputSpec {
    fn from(value: &PkgInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            namespace: value.namespace.clone(),
            name: value.name.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.as_ref().map(|e| e.iter().map(|e| e.into()).collect()),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&PackageQualifierInputSpec> for ingest_dependency::PackageQualifierInputSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<MatchFlags> for ingest_dependency::MatchFlags {
    fn from(value: MatchFlags) -> Self {
        Self {
            pkg: (&value.pkg).into(),
        }
    }
}

impl From<&PkgMatchType> for ingest_dependency::PkgMatchType {
    fn from(value: &PkgMatchType) -> Self {
        match value {
            PkgMatchType::AllVersions => Self::ALL_VERSIONS,
            PkgMatchType::SpecificVersion => Self::SPECIFIC_VERSION,
        }
    }
}

impl From<&IsDependencyInputSpec> for ingest_dependency::IsDependencyInputSpec {
    fn from(value: &IsDependencyInputSpec) -> Self {
        Self {
            version_range: value.version_range.clone(),
            dependency_type: (&value.dependency_type).into(),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            document_ref: value.document_ref.clone(),
        }
    }
}

impl From<&DependencyType> for ingest_dependency::DependencyType {
    fn from(value: &DependencyType) -> Self {
        match value {
            DependencyType::Direct => Self::DIRECT,
            DependencyType::Indirect => Self::INDIRECT,
            DependencyType::Unknown => Self::UNKNOWN,
        }
    }
}

impl From<&IDorPkgInput> for ingest_dependency::IDorPkgInput {
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
