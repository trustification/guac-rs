use crate::client::intrinsic::is_dependency::{DependencyType, IsDependency, IsDependencySpec};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion,
    PkgSpec,
};
use graphql_client::GraphQLQuery;

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
            package: value.package.as_ref().map(|inner| inner.into()),
            dependent_package: value.dependent_package.as_ref().map(|inner| inner.into()),
            version_range: value.version_range.clone(),
            dependency_type: value.dependency_type.as_ref().map(|inner| inner.into()),
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
            qualifiers: value
                .qualifiers
                .as_ref()
                .map(|inner| inner.iter().map(|e| e.into()).collect()),
            match_only_empty_qualifiers: value.match_only_empty_qualifiers,
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
            DependencyType::Direct => Self::DIRECT,
            DependencyType::Indirect => Self::INDIRECT,
            DependencyType::Unknown => Self::UNKNOWN,
        }
    }
}

impl From<&query_is_dependency::allIsDependencyTree> for IsDependency {
    fn from(value: &query_is_dependency::allIsDependencyTree) -> Self {
        Self {
            id: value.id.clone(),
            package: (&value.package).into(),
            dependent_package: (&value.dependent_package).into(),
            version_range: value.version_range.clone(),
            dependency_type: (&value.dependency_type).into(),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&query_is_dependency::allPackageTree> for Package {
    fn from(value: &query_is_dependency::allPackageTree) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_is_dependency::DependencyType> for DependencyType {
    fn from(value: &query_is_dependency::DependencyType) -> Self {
        match value {
            query_is_dependency::DependencyType::DIRECT => DependencyType::Direct,
            query_is_dependency::DependencyType::INDIRECT => DependencyType::Indirect,
            query_is_dependency::DependencyType::UNKNOWN => DependencyType::Unknown,
            query_is_dependency::DependencyType::Other(_) => DependencyType::Unknown,
        }
    }
}

impl From<&query_is_dependency::AllPackageTreeNamespaces> for PackageNamespace {
    fn from(value: &query_is_dependency::AllPackageTreeNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_is_dependency::AllPackageTreeNamespacesNames> for PackageName {
    fn from(value: &query_is_dependency::AllPackageTreeNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_is_dependency::AllPackageTreeNamespacesNamesVersions> for PackageVersion {
    fn from(value: &query_is_dependency::AllPackageTreeNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&query_is_dependency::AllPackageTreeNamespacesNamesVersionsQualifiers>
    for PackageQualifier
{
    fn from(value: &query_is_dependency::AllPackageTreeNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}
