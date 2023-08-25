use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion,
    PkgSpec,
};
use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use std::str::FromStr;

//use self::query_packages::PackageQualifierSpec;

//use self::query_packages::allPkgTree;
//use self::query_packages::PkgSpec;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/package/package.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryPackages;

impl From<&PkgSpec> for query_packages::PkgSpec {
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

impl From<&PackageQualifierSpec> for query_packages::PackageQualifierSpec {
    fn from(value: &PackageQualifierSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&query_packages::allPkgTree> for Package {
    fn from(value: &query_packages::allPkgTree) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_packages::AllPkgTreeNamespaces> for PackageNamespace {
    fn from(value: &query_packages::AllPkgTreeNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_packages::AllPkgTreeNamespacesNames> for PackageName {
    fn from(value: &query_packages::AllPkgTreeNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_packages::AllPkgTreeNamespacesNamesVersions> for PackageVersion {
    fn from(value: &query_packages::AllPkgTreeNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&query_packages::AllPkgTreeNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &query_packages::AllPkgTreeNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}
