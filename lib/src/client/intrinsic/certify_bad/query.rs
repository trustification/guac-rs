use graphql_client::GraphQLQuery;
use serde::Serialize;
use std::str::FromStr;
use crate::client::intrinsic::certify_bad::{CertifyBad, CertifyBadSpec};
use crate::client::intrinsic::package::{Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion, PkgSpec};
use crate::client::intrinsic::{PackageSourceOrArtifact, PackageSourceOrArtifactSpec};


#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_bad/certify_bad.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryCertifyBad;


impl From<&CertifyBadSpec> for query_certify_bad::CertifyBadSpec {
    fn from(value: &CertifyBadSpec) -> Self {
        Self {
            id: value.id.clone(),
            subject: value.subject.as_ref().map(|inner| inner.into()),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&PackageSourceOrArtifactSpec> for query_certify_bad::PackageSourceOrArtifactSpec {
    fn from(value: &PackageSourceOrArtifactSpec) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None,
            source: None,
        }
    }
}

impl From<&PkgSpec> for query_certify_bad::PkgSpec {
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

impl From<&PackageQualifierSpec> for query_certify_bad::PackageQualifierSpec {
    fn from(value: &PackageQualifierSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&query_certify_bad::allCertifyBadTree> for CertifyBad {
    fn from(value: &query_certify_bad::allCertifyBadTree) -> Self {
        Self {
            id: value.id.clone(),
            subject: (&value.subject).into(),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&query_certify_bad::AllCertifyBadTreeSubject> for PackageSourceOrArtifact {
    fn from(value: &query_certify_bad::AllCertifyBadTreeSubject) -> Self {
        match value {
            query_certify_bad::AllCertifyBadTreeSubject::Package(inner) => {
                Self::Package(
                    inner.into()
                )
            }
            query_certify_bad::AllCertifyBadTreeSubject::Source(inner) => {
                todo!()
            }
            query_certify_bad::AllCertifyBadTreeSubject::Artifact(inner) => {
                todo!()
            }
        }
    }
}

impl From<&query_certify_bad::AllCertifyBadTreeSubjectOnPackage> for Package {
    fn from(value: &query_certify_bad::AllCertifyBadTreeSubjectOnPackage) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e|
                e.into()
            ).collect()
        }
    }
}

impl From<&query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespaces> for PackageNamespace {
    fn from(value: &query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| {
                e.into()
            }).collect()
        }
    }
}

impl From<&query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespacesNames> for PackageName {
    fn from(value: &query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| {
                e.into()
            }).collect()
        }
    }
}

impl From<&query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespacesNamesVersions> for PackageVersion {
    fn from(value: &query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| {
                e.into()
            }).collect(),
            subpath: value.subpath.clone(),
        }
    }
}


impl From<&query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &query_certify_bad::AllCertifyBadTreeSubjectOnPackageNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}
