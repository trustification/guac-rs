mod query;

use crate::client::graph::Node;
use crate::client::semantic::spog::query::QuerySpog;

use crate::client::intrinsic::certify_vex_statement::{self, CertifyVexStatement, VexJustification, VexStatus};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion,
    PkgSpec,
};
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
        let response_body =
            post_graphql::<QuerySpog, _>(self.intrinsic().client(), self.intrinsic().url(), variables).await?;

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
}

#[derive(Debug, Clone)]
pub struct ProductByCve {
    pub root: Package,
    pub vex: CertifyVexStatement,
    pub path: Vec<Package>,
}