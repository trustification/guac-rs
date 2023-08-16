use self::query_dependents::{AllIsDependencyTreePackage, PkgNameSpec};
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

impl TryFrom<&str> for PkgNameSpec {
    type Error = packageurl::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;

        Ok(PkgNameSpec {
            id: None,
            type_: Some(purl.ty().to_string()),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: Some(purl.name().to_string()),
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
