use graphql_client::GraphQLQuery;
use crate::client::intrinsic::is_dependency::{DependencyType, IsDependencySpec};
use crate::client::intrinsic::package::{PackageQualifierSpec, PkgSpec};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/is_dependency/is_dependency.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryIsDependency;

impl From<&IsDependencySpec> for query_is_dependency::IsDependencySpec {
    fn from(value: &IsDependencySpec) -> Self {
        Self {
            id: value.id.clone(),
            package: value.package.as_ref().map(|inner|inner.into()),
            dependent_package: value.dependent_package.as_ref().map(|inner|inner.into()),
            version_range: value.version_range.clone(),
            dependency_type: value.dependency_type.as_ref().map(|inner|inner.into()),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}


impl From<&PkgSpec> for query_is_dependency::PkgSpec {
    fn from(value: &PkgSpec) -> Self {
        Self {
            id: value.id.clone(),
            type_: value.r#type.clone(),
            namespace: value.namespace.clone(),
            name: value.name.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.as_ref().map(|inner| {
                inner.iter().map(|e| {
                    e.into()
                }).collect()
            }),
            match_only_empty_qualifiers: value.match_only_empty_qualifiers.clone(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&PackageQualifierSpec> for query_is_dependency::PackageQualifierSpec {
    fn from(value: &PackageQualifierSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&DependencyType> for query_is_dependency::DependencyType {
    fn from(value: &DependencyType) -> Self {
        match value {
            DependencyType::Direct => {
                Self::DIRECT
            }
            DependencyType::Indirect => {
                Self::INDIRECT
            }
            DependencyType::Unknown => {
                Self::UNKNOWN
            }
        }
    }
}