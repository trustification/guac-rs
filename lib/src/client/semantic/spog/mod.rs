mod find_vulnerability;
mod query;

use std::collections::{BTreeSet, HashMap};

use crate::client::graph::Node;
use crate::client::intrinsic::certify_vuln::CertifyVuln;
use crate::client::semantic::spog::find_vulnerability::FindVulnerability;
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

    pub async fn find_vulnerability(
        &self,
        purl: &str,
    ) -> Result<HashMap<String, BTreeSet<String>>, Error> {
        use self::find_vulnerability::find_vulnerability;

        let variables = find_vulnerability::Variables {
            purl: purl.to_string(),
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
                            for pkg in inner.try_as_purls()? {
                                let entry =
                                    result.entry(pkg.to_string()).or_insert(BTreeSet::new());
                                entry.extend(
                                    vex.vulnerability
                                        .vulnerability_ids
                                        .iter()
                                        .map(|v| v.vulnerability_id.clone())
                                        .collect::<Vec<_>>(),
                                );
                            }
                        }
                        _ => {}
                    };
                }
                find_vulnerability::FindVulnerabilityFindVulnerability::CertifyVuln(inner) => {
                    let cert = CertifyVuln::from(inner);
                    for pkg in cert.package.try_as_purls()? {
                        let entry = result.entry(pkg.to_string()).or_insert(BTreeSet::new());
                        entry.extend(
                            cert.vulnerability
                                .vulnerability_ids
                                .iter()
                                .map(|v| v.vulnerability_id.clone())
                                .collect::<Vec<_>>(),
                        );
                    }
                }
            }
        }

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct ProductByCve {
    pub root: Package,
    pub vex: CertifyVexStatement,
    pub path: Vec<Package>,
}
