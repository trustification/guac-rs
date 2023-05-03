use graphql_client::GraphQLQuery;
use self::certify_vuln_q2::AllCertifyVulnTreePackage;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct CertifyVulnQ2;

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
                        data.push(format!(
                            "{}={}",
                            entry.key,
                            entry.value
                        ));
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
