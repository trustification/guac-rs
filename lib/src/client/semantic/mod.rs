use std::collections::HashMap;

use packageurl::PackageUrl;

use crate::client::graph::{Edge, Node};
use crate::client::intrinsic::is_dependency::IsDependencySpec;
use crate::client::intrinsic::vulnerability::VulnerabilitySpec;
use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::semantic::ingest::{Predicate, Subject};
use crate::client::{Error, GuacClient};

pub mod ingest;

pub struct SemanticGuacClient {
    client: GuacClient,
}

impl SemanticGuacClient {
    pub(crate) fn new(client: &GuacClient) -> Self {
        Self {
            client: client.clone(),
        }
    }

    pub fn intrinsic(&self) -> IntrinsicGuacClient {
        IntrinsicGuacClient::new(&self.client)
    }

    pub async fn ingest<S: Subject, P: Predicate<S>>(
        &self,
        subject: &S,
        predicate: &P,
    ) -> Result<(), Error> {
        predicate.apply(&self.client, subject).await
    }

    pub async fn dependencies_of<'a, 'b>(
        &self,
        package: &PackageUrl<'a>,
    ) -> Result<Vec<PackageUrl<'b>>, Error> {
        let is_dependencies = self
            .intrinsic()
            .is_dependency(&IsDependencySpec {
                package: Some(package.clone().into()),
                ..Default::default()
            })
            .await?;

        let mut dependencies = Vec::new();

        for is_dependency in is_dependencies {
            for dep in is_dependency.dependent_package.try_as_purls()? {
                if !dependencies.contains(&dep) {
                    dependencies.push(dep);
                }
            }
        }

        Ok(dependencies)
    }

    pub async fn dependents_of<'a, 'b>(
        &self,
        package: &PackageUrl<'a>,
    ) -> Result<Vec<PackageUrl<'b>>, Error> {
        let is_dependencies = self
            .intrinsic()
            .is_dependency(&IsDependencySpec {
                dependent_package: Some(package.clone().into()),
                ..Default::default()
            })
            .await?;

        let mut dependents = Vec::new();

        for is_dependency in is_dependencies {
            for dep in is_dependency.package.try_as_purls()? {
                if !dependents.contains(&dep) {
                    dependents.push(dep);
                }
            }
        }

        Ok(dependents)
    }

    pub async fn transitive_affected_paths_of<'a>(
        &self,
        vuln_id: &str,
    ) -> Result<Vec<Vec<PackageUrl<'a>>>, Error> {
        let intrinsic = self.intrinsic();

        let vulns = intrinsic
            .vulnerabilities(&VulnerabilitySpec {
                id: None,
                r#type: None,
                vulnerability_id: Some(vuln_id.to_string()),
                no_vuln: None,
            })
            .await?;

        let mut roots = Vec::default();

        for vuln in vulns {
            for id in &vuln.vulnerability_ids {
                //println!("VULN {:?}", vuln);
                let first_order_affected = intrinsic
                    .neighbors(&id.id, vec![Edge::VulnerabilityCertifyVuln])
                    .await?;

                for each in first_order_affected {
                    println!("FIRST: {:?}", each);
                    if let Node::CertifyVuln(cert) = each {
                        let purls = cert.package.try_as_purls()?;

                        for purl in &purls {
                            if !roots.contains(purl) {
                                roots.push(purl.clone())
                            }
                        }
                    }
                }
            }
        }

        let mut paths = Vec::new();

        for root in roots {
            paths.extend_from_slice(&self.transitive_dependent_paths_of(&root).await?);
        }

        //println!("roots {:?}", roots);

        Ok(paths)
    }

    pub async fn transitive_affected_of<'a>(
        &self,
        vuln_id: &str,
    ) -> Result<Vec<PackageUrl<'a>>, Error> {
        let mut affected = Vec::new();

        let paths = self.transitive_affected_paths_of(vuln_id).await?;

        for path in &paths {
            if let Some(tail) = path.last() {
                if !affected.contains(tail) {
                    affected.push(tail.clone())
                }
            }
        }

        Ok(affected)
    }

    pub async fn transitive_dependent_paths_of<'a>(
        &self,
        package: &PackageUrl<'a>,
    ) -> Result<Vec<Vec<PackageUrl<'a>>>, Error> {
        let intrinsic = self.intrinsic();

        let mut queue = Vec::new();
        queue.push(package.clone());

        let mut segments = HashMap::new();

        while let Some(cur) = queue.pop() {
            let dependents = self.dependents_of(&cur).await?;
            for each in &dependents {
                if !segments.contains_key(&each.to_string()) {
                    queue.push(each.clone());
                }
            }
            segments.insert(cur.to_string(), dependents);
        }

        let mut paths = Vec::new();
        let mut queue = Vec::new();

        queue.push(vec![package.clone()]);
        while let Some(cur) = queue.pop() {
            if let Some(tail) = cur.last() {
                if let Some(next) = segments.get(&tail.to_string()) {
                    for each in next {
                        let mut todo = cur.clone();
                        todo.push(each.clone());
                        queue.push(todo);
                    }
                    paths.push(cur);
                } else {
                    paths.push(cur);
                }
            }
        }

        Ok(paths)
    }

    pub async fn transitive_dependents_of<'a>(
        &self,
        package: &PackageUrl<'a>,
    ) -> Result<Vec<PackageUrl<'a>>, Error> {
        let mut dependents = Vec::new();

        for path in self.transitive_dependent_paths_of(package).await? {
            if let Some(tail) = path.last() {
                if !dependents.contains(tail) {
                    dependents.push(tail.clone())
                }
            }
        }

        Ok(dependents)
    }
}
