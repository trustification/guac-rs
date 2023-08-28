use std::borrow::Cow;

use graphql_client::reqwest::post_graphql;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};

use crate::client::intrinsic::package::ingest::ingest_package::allPkgTree;
use crate::client::intrinsic::package::ingest::IngestPackage;
use crate::client::intrinsic::package::query::QueryPackages;
use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::{Error, Id};
//use crate::client::intrinsic::package::query::query_package::PackageQualifierSpec;

mod ingest;
mod query;

fn extract_deep_id(tree: &allPkgTree) -> Id {
    if tree.namespaces.is_empty() {
        return tree.id.clone();
    }

    if tree.namespaces[0].names.is_empty() {
        return tree.namespaces[0].id.clone();
    }

    if tree.namespaces[0].names[0].versions.is_empty() {
        return tree.namespaces[0].names[0].id.clone();
    }

    tree.namespaces[0].names[0].versions[0].id.clone()
}

impl IntrinsicGuacClient {
    pub async fn ingest_package(&self, package: &PkgInputSpec) -> Result<Id, Error> {
        use self::ingest::ingest_package;
        let variables = ingest_package::Variables {
            package: package.into(),
        };

        let response_body =
            post_graphql::<IngestPackage, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(extract_deep_id(&data.ingest_package))
    }

    pub async fn packages(&self, package: &PkgSpec) -> Result<Vec<Package>, Error> {
        use self::query::query_packages;
        let variables = query_packages::Variables {
            package: package.into(),
        };

        let response_body =
            post_graphql::<QueryPackages, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let packages = data.packages.iter().map(|e| e.into()).collect();

        Ok(packages)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Package {
    pub id: String,
    pub r#type: String,
    pub namespaces: Vec<PackageNamespace>,
}

impl Package {
    pub fn try_as_purls<'p>(&self) -> Result<Vec<PackageUrl<'p>>, packageurl::Error> {
        let mut purls = Vec::new();

        for ns in &self.namespaces {
            for name in &ns.names {
                let purl = PackageUrl::new(self.r#type.clone(), name.name.clone())?;
                if name.versions.is_empty() {
                    purls.push(purl);
                } else {
                    for version in &name.versions {
                        let mut purl = purl.clone();
                        purl.with_version(version.version.clone());

                        for qualifier in &version.qualifiers {
                            purl.add_qualifier(qualifier.key.clone(), qualifier.value.clone())?;
                        }

                        purls.push(purl);
                    }
                }
            }
        }

        Ok(purls)
    }

    pub fn matches_exact(&self, purl: PackageUrl<'_>) -> bool {
        if let Ok(purls) = self.try_as_purls() {
            purls.contains(&purl)
        } else {
            false
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PackageNamespace {
    pub id: String,
    pub namespace: String,
    pub names: Vec<PackageName>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PackageName {
    pub id: String,
    pub name: String,
    pub versions: Vec<PackageVersion>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PackageVersion {
    pub id: String,
    pub version: String,
    pub qualifiers: Vec<PackageQualifier>,
    pub subpath: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PackageQualifier {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct PkgSpec {
    pub id: Option<String>,
    pub r#type: Option<String>,
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub qualifiers: Option<Vec<PackageQualifierSpec>>,
    pub match_only_empty_qualifiers: Option<bool>,
    pub subpath: Option<String>,
}

impl From<&Package> for PkgSpec {
    fn from(value: &Package) -> Self {
        Self {
            id: Some(value.id.clone()),
            r#type: None,
            namespace: None,
            name: None,
            version: None,
            qualifiers: None,
            match_only_empty_qualifiers: None,
            subpath: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackageQualifierSpec {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PkgInputSpec {
    pub r#type: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: Option<Vec<PackageQualifierInputSpec>>,
    pub subpath: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackageQualifierInputSpec {
    pub key: String,
    pub value: String,
}

impl From<PackageUrl<'_>> for PkgInputSpec {
    fn from(purl: PackageUrl<'_>) -> Self {
        Self {
            r#type: purl.ty().to_owned(),
            namespace: purl.namespace().map(|e| e.to_owned()),
            name: purl.name().to_owned(),
            version: purl.version().map(|e| e.to_owned()),
            qualifiers: Some(
                purl.qualifiers()
                    .iter()
                    .map(|(key, value)| (key, value).into())
                    .collect(),
            ),
            subpath: purl.subpath().map(|e| e.to_owned()),
        }
    }
}

impl From<PackageUrl<'_>> for PkgSpec {
    fn from(purl: PackageUrl<'_>) -> Self {
        Self {
            id: None,
            r#type: Some(purl.ty().to_owned()),
            namespace: purl.namespace().map(|e| e.to_owned()),
            name: Some(purl.name().to_owned()),
            version: purl.version().map(|e| e.to_owned()),
            qualifiers: Some(
                purl.qualifiers()
                    .iter()
                    .map(|(key, value)| (key, value).into())
                    .collect(),
            ),
            match_only_empty_qualifiers: None,
            subpath: purl.subpath().map(|e| e.to_owned()),
        }
    }
}

impl From<(&Cow<'_, str>, &Cow<'_, str>)> for PackageQualifierInputSpec {
    fn from((key, value): (&Cow<'_, str>, &Cow<'_, str>)) -> Self {
        PackageQualifierInputSpec {
            key: key.to_string(),
            value: value.to_string(),
        }
    }
}

impl From<(&Cow<'_, str>, &Cow<'_, str>)> for PackageQualifierSpec {
    fn from((key, value): (&Cow<'_, str>, &Cow<'_, str>)) -> Self {
        PackageQualifierSpec {
            key: key.to_string(),
            value: Some(value.to_string()),
        }
    }
}

impl From<&PkgInputSpec> for PkgSpec {
    fn from(value: &PkgInputSpec) -> Self {
        Self {
            id: None,
            r#type: Some(value.r#type.clone()),
            namespace: value.namespace.clone(),
            name: Some(value.name.clone()),
            version: value.version.clone(),
            qualifiers: value
                .qualifiers
                .as_ref()
                .map(|inner| inner.iter().map(|e| e.into()).collect()),
            match_only_empty_qualifiers: None,
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&PackageQualifierInputSpec> for PackageQualifierSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: Some(value.value.clone()),
        }
    }
}

impl TryFrom<&Package> for Vec<PackageUrl<'_>> {
    type Error = packageurl::Error;
    fn try_from(value: &Package) -> Result<Self, Self::Error> {
        value.try_as_purls()
    }
}
