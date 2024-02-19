use chrono::Utc;
use graphql_client::GraphQLQuery;

use crate::client::intrinsic::certify_good::{CertifyGood, CertifyGoodSpec};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion, PkgSpec,
};
use crate::client::intrinsic::{PackageSourceOrArtifact, PackageSourceOrArtifactSpec};

type Time = chrono::DateTime<Utc>;
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_good/certify_good.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryCertifyGood;

impl From<&CertifyGoodSpec> for query_certify_good::CertifyGoodSpec {
    fn from(value: &CertifyGoodSpec) -> Self {
        Self {
            id: value.id.clone(),
            subject: value.subject.as_ref().map(|inner| inner.into()),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            known_since: value.known_since,
        }
    }
}

impl From<&PackageSourceOrArtifactSpec> for query_certify_good::PackageSourceOrArtifactSpec {
    fn from(value: &PackageSourceOrArtifactSpec) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None,
            source: None,
        }
    }
}

impl From<&PkgSpec> for query_certify_good::PkgSpec {
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

impl From<&PackageQualifierSpec> for query_certify_good::PackageQualifierSpec {
    fn from(value: &PackageQualifierSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&query_certify_good::allCertifyGoodTree> for CertifyGood {
    fn from(value: &query_certify_good::allCertifyGoodTree) -> Self {
        Self {
            id: value.id.clone(),
            subject: (&value.subject).into(),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            known_since: None,
        }
    }
}

impl From<&query_certify_good::AllCertifyGoodTreeSubject> for PackageSourceOrArtifact {
    fn from(value: &query_certify_good::AllCertifyGoodTreeSubject) -> Self {
        match value {
            query_certify_good::AllCertifyGoodTreeSubject::Package(inner) => Self::Package(inner.into()),
            query_certify_good::AllCertifyGoodTreeSubject::Source(_inner) => {
                todo!()
            }
            query_certify_good::AllCertifyGoodTreeSubject::Artifact(_inner) => {
                todo!()
            }
        }
    }
}

impl From<&query_certify_good::AllCertifyGoodTreeSubjectOnPackage> for Package {
    fn from(value: &query_certify_good::AllCertifyGoodTreeSubjectOnPackage) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespaces> for PackageNamespace {
    fn from(value: &query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespacesNames> for PackageName {
    fn from(value: &query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespacesNamesVersions> for PackageVersion {
    fn from(value: &query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespacesNamesVersionsQualifiers>
    for PackageQualifier
{
    fn from(value: &query_certify_good::AllCertifyGoodTreeSubjectOnPackageNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}
