mod dependent_product;
mod find_vulnerability;
mod find_vulnerability_by_sbom_uri;
mod query;

use std::collections::{BTreeSet, HashMap};

use crate::client::graph::Node;
use crate::client::intrinsic::certify_vuln::CertifyVuln;
use crate::client::semantic::spog::dependent_product::FindDependentProduct;
use crate::client::semantic::spog::find_vulnerability::FindVulnerability;
use crate::client::semantic::spog::find_vulnerability_by_sbom_uri::FindVulnerabilityBySbomURI;
use crate::client::semantic::spog::query::QuerySpog;

use crate::client::intrinsic::certify_vex_statement::{
    self, CertifyVexStatement, VexJustification, VexStatus,
};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion,
    PkgSpec,
};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId};
use crate::client::intrinsic::PackageOrArtifact::Package as SubjectPackage;
use crate::client::semantic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerability as QS;
use crate::client::semantic::SemanticGuacClient;

use crate::client::{Error, Id};
use chrono::Utc;
use graphql_client::reqwest::post_graphql;
use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use serde_json::json;

type Time = chrono::DateTime<Utc>;

impl SemanticGuacClient {
    pub async fn product_by_cve(&self, vulnerability_id: &str) -> Result<Vec<ProductByCve>, Error> {
        use self::query::query_spog;

        let variables = query_spog::Variables {
            vulnerability_id: vulnerability_id.to_string(),
        };
        let response_body = post_graphql::<QuerySpog, _>(
            self.intrinsic().client(),
            self.intrinsic().url(),
            variables,
        )
        .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data: <QuerySpog as GraphQLQuery>::ResponseData =
            response_body.data.ok_or(Error::GraphQL(vec![]))?;
        let mut res = Vec::new();

        for entry in &data.find_top_level_packages_related_to_vulnerability {
            let len = entry.len();
            let root = match &entry[len - 1] {
                QS::Package(inner) => Package::from(inner),
                _ => return Err(Error::GraphQL(vec![])),
            };

            let vex = match &entry[0] {
                QS::CertifyVEXStatement(inner) => CertifyVexStatement::from(inner),
                _ => return Err(Error::GraphQL(vec![])),
            };
            let mut path = Vec::new();
            for value in &entry[1..len - 1] {
                match value {
                    QS::Package(inner) => {
                        path.push(Package::from(inner));
                    }
                    val => {
                        //skipping
                    }
                }
            }
            let item = ProductByCve { root, vex, path };
            res.push(item);
        }

        Ok(res)
    }

    pub async fn find_vulnerability_statuses(
        &self,
        purl: &str,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<VulnerabilityStatus>, Error> {
        use self::find_vulnerability::find_vulnerability;

        let variables = find_vulnerability::Variables {
            purl: purl.to_string(),
            offset,
            limit,
        };
        let response_body = post_graphql::<FindVulnerability, _>(
            self.intrinsic().client(),
            self.intrinsic().url(),
            variables,
        )
        .await?;

        if let Some(errors) = response_body.errors {
            //TODO fix query not to return error in this case
            for error in errors.clone().into_iter() {
                if error.message == "failed to locate package based on purl" {
                    return Ok(Vec::new());
                }
            }
            return Err(Error::GraphQL(errors));
        }

        let data: <FindVulnerability as GraphQLQuery>::ResponseData =
            response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut result = Vec::new();

        for entry in &data.find_vulnerability {
            match entry {
                find_vulnerability::FindVulnerabilityFindVulnerability::CertifyVEXStatement(
                    inner,
                ) => {
                    let vex: CertifyVexStatement = CertifyVexStatement::from(inner);
                    match vex.subject {
                        SubjectPackage(inner) => {
                            for v in vex.vulnerability.vulnerability_ids {
                                result.push(VulnerabilityStatus {
                                    id: v.vulnerability_id.clone(),
                                    status: Some(vex.status.clone()),
                                    justification: Some(vex.vex_justification.clone()),
                                });
                            }
                        }
                        _ => {}
                    };
                }
                find_vulnerability::FindVulnerabilityFindVulnerability::CertifyVuln(inner) => {
                    let cert = CertifyVuln::from(inner);
                    for v in cert.vulnerability.vulnerability_ids {
                        result.push(VulnerabilityStatus {
                            id: v.vulnerability_id.clone(),
                            status: None,
                            justification: None,
                        });
                    }
                }
            }
        }

        Ok(result)
    }

    pub async fn find_vulnerability(
        &self,
        purl: &str,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<HashMap<String, BTreeSet<String>>, Error> {
        use self::find_vulnerability::find_vulnerability;

        let variables = find_vulnerability::Variables {
            purl: purl.to_string(),
            offset,
            limit,
        };
        let response_body = post_graphql::<FindVulnerability, _>(
            self.intrinsic().client(),
            self.intrinsic().url(),
            variables,
        )
        .await?;

        if let Some(errors) = response_body.errors {
            //TODO fix query not to return error in this case
            for error in errors.clone().into_iter() {
                if error.message == "failed to locate package based on purl" {
                    return Ok(HashMap::new());
                }
            }
            return Err(Error::GraphQL(errors));
        }

        let data: <FindVulnerability as GraphQLQuery>::ResponseData =
            response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut result: HashMap<String, BTreeSet<String>> = HashMap::new();

        for entry in &data.find_vulnerability {
            match entry {
                find_vulnerability::FindVulnerabilityFindVulnerability::CertifyVEXStatement(
                    inner,
                ) => {
                    let vex: CertifyVexStatement = CertifyVexStatement::from(inner);
                    match vex.subject {
                        SubjectPackage(inner) => {
                            for v in vex.vulnerability.vulnerability_ids {
                                let entry =
                                    result.entry(v.vulnerability_id).or_insert(BTreeSet::new());
                                entry.extend(inner.try_as_purls()?.iter().map(|p| p.to_string()));
                            }
                        }
                        _ => {}
                    };
                }
                find_vulnerability::FindVulnerabilityFindVulnerability::CertifyVuln(inner) => {
                    let cert = CertifyVuln::from(inner);
                    for v in cert.vulnerability.vulnerability_ids {
                        let entry = result.entry(v.vulnerability_id).or_insert(BTreeSet::new());
                        entry.extend(cert.package.try_as_purls()?.iter().map(|p| p.to_string()));
                    }
                }
            }
        }

        Ok(result)
    }

    pub async fn find_vulnerability_by_sbom_uri(
        &self,
        sbom_uri: &str,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<HashMap<String, BTreeSet<String>>, Error> {
        use self::find_vulnerability_by_sbom_uri::find_vulnerability_by_sbom_uri;

        let variables = find_vulnerability_by_sbom_uri::Variables {
            sbom_uri: sbom_uri.to_string(),
            offset,
            limit,
        };
        let response_body: graphql_client::Response<
            <FindVulnerabilityBySbomURI as GraphQLQuery>::ResponseData,
        > = post_graphql::<FindVulnerabilityBySbomURI, _>(
            self.intrinsic().client(),
            self.intrinsic().url(),
            variables,
        )
        .await?;

        if let Some(errors) = response_body.errors {
            //TODO fix query not to return error in this case
            for error in errors.clone().into_iter() {
                if error.message == "failed to locate package based on purl" {
                    return Ok(HashMap::new());
                }
            }
            return Err(Error::GraphQL(errors));
        }

        let data: <FindVulnerabilityBySbomURI as GraphQLQuery>::ResponseData =
            response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut result: HashMap<String, BTreeSet<String>> = HashMap::new();

        for entry in &data.find_vulnerability_by_sbom_uri {
            match entry {
                find_vulnerability_by_sbom_uri::FindVulnerabilityBySbomUriFindVulnerabilityBySbomUri::CertifyVEXStatement(
                    inner,
                ) => {
                    let vex: CertifyVexStatement = CertifyVexStatement::from(inner);
                    // TODO make status filter list configurable
                    if vex.status == VexStatus::Affected {
                        match vex.subject {
                            SubjectPackage(inner) => {
                                for v in vex.vulnerability.vulnerability_ids {
                                    let entry =
                                        result.entry(v.vulnerability_id).or_insert(BTreeSet::new());
                                    entry.extend(inner.try_as_purls()?.iter().map(|p| p.to_string()));
                                }
                            }
                            _ => {}
                        };
                    }
                }
                find_vulnerability_by_sbom_uri::FindVulnerabilityBySbomUriFindVulnerabilityBySbomUri::CertifyVuln(inner) => {
                    let cert = CertifyVuln::from(inner);
                    for v in cert.vulnerability.vulnerability_ids {
                        let entry = result.entry(v.vulnerability_id).or_insert(BTreeSet::new());
                        entry.extend(cert.package.try_as_purls()?.iter().map(|p| p.to_string()));
                    }
                }
            }
        }

        Ok(result)
    }

    pub async fn find_dependent_product(
        &self,
        purl: &str,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<String>, Error> {
        use self::dependent_product::find_dependent_product;

        let variables = find_dependent_product::Variables {
            purl: purl.to_string(),
            offset,
            limit,
        };
        let response_body: graphql_client::Response<
            <FindDependentProduct as GraphQLQuery>::ResponseData,
        > = post_graphql::<FindDependentProduct, _>(
            self.intrinsic().client(),
            self.intrinsic().url(),
            variables,
        )
        .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data: <FindDependentProduct as GraphQLQuery>::ResponseData =
            response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let result = data
            .find_dependent_product
            .iter()
            .map(|entry| entry.uri.clone())
            .collect();

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct ProductByCve {
    pub root: Package,
    pub vex: CertifyVexStatement,
    pub path: Vec<Package>,
}

#[derive(Serialize, Deserialize)]
pub struct VulnerabilityStatus {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<VexStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<VexJustification>,
}
