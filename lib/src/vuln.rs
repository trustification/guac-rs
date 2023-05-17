use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use std::str::FromStr;

use self::certify_vuln_q1::{AllCertifyVulnTreePackage, PackageQualifierSpec, PkgSpec};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct CertifyVulnQ1;

impl TryFrom<&str> for PkgSpec {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;
        let mut qualifiers = Vec::new();
        for (key, value) in purl.qualifiers().iter() {
            qualifiers.push(PackageQualifierSpec {
                key: key.to_string(),
                value: Some(value.to_string()),
            })
        }

        Ok(PkgSpec {
            id: None,
            type_: Some(purl.ty().to_string()),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: Some(purl.name().to_string()),
            subpath: purl.subpath().map(|s| s.to_string()),
            version: purl.version().map(|s| s.to_string()),
            qualifiers: if qualifiers.is_empty() {
                None
            } else {
                Some(qualifiers)
            },
            match_only_empty_qualifiers: Some(false),
        })
    }
}

pub fn vuln2purls(pkg: &AllCertifyVulnTreePackage) -> Vec<String> {
    let mut purls = Vec::new();
    let t = &pkg.type_;
    for namespace in pkg.namespaces.iter() {
        for name in namespace.names.iter() {
            for version in name.versions.iter() {
                let qualifiers = if version.qualifiers.is_empty() {
                    String::new()
                } else {
                    let mut data: Vec<String> = Vec::new();
                    for entry in version.qualifiers.iter() {
                        data.push(format!("{}={}", entry.key, entry.value));
                    }
                    let data = data.join("&");
                    format!("?{}", data)
                };
                let purl = format!(
                    "pkg:{}/{}/{}@{}{}",
                    t, namespace.namespace, name.name, version.version, qualifiers
                );
                purls.push(purl);
            }
        }
    }
    purls
}
