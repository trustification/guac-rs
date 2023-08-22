use self::query_dependents::{AllIsDependencyTreePackage, PkgSpec, PackageQualifierSpec};
use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use std::str::FromStr;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/schema.json",
    query_path = "src/client/is_dependency/is_dependency.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryDependents;

impl TryFrom<&str> for PkgSpec {
    type Error = packageurl::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;

        Ok(PkgSpec {
            id: None,
            type_: Some(purl.ty().to_string()),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: Some(purl.name().to_string()),
            qualifiers: Some(purl.qualifiers()
                .iter().map(|(k,v)| {
                PackageQualifierSpec {
                    key: k.to_string(),
                    value: Some(v.to_string()),
                }
            }).collect()),
            version: purl.version().map(|v| v.to_owned()),
            subpath: purl.subpath().map(|sp| sp.to_owned()),
            match_only_empty_qualifiers: None,
        })
    }
}


pub fn deps2purls(pkg: &AllIsDependencyTreePackage) -> Vec<String> {
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
                        data.push(format!("{}={}", entry.key, entry.value,));
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
