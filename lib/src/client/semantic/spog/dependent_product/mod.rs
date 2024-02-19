#![allow(clippy::all, warnings)]
pub struct FindDependentProduct;
pub mod find_dependent_product {
    #![allow(dead_code)]
    use std::result::Result;
    pub const OPERATION_NAME: &str = "FindDependentProduct";
    pub const QUERY : & str = "query FindDependentProduct($purl: String!, $offset: Int, $limit: Int) {\n  findDependentProduct(purl: $purl, offset: $offset, limit: $limit) {\n    uri\n    subject {\n      __typename\n      ... on Package {\n      type\n      namespaces {\n        namespace\n        names {\n          name\n          versions {\n            id\n            version\n            qualifiers {\n              key\n              value\n            }\n            subpath\n            }\n        }\n      }\n    }\n    }\n  }\n}\n" ;
    use super::*;
    use serde::{Deserialize, Serialize};
    #[allow(dead_code)]
    type Boolean = bool;
    #[allow(dead_code)]
    type Float = f64;
    #[allow(dead_code)]
    type Int = i64;
    #[allow(dead_code)]
    type ID = String;
    #[derive(Serialize)]
    pub struct Variables {
        pub purl: String,
        pub offset: Option<Int>,
        pub limit: Option<Int>,
    }
    impl Variables {}
    #[derive(Deserialize, Debug)]
    pub struct ResponseData {
        #[serde(rename = "findDependentProduct")]
        pub find_dependent_product: Vec<FindDependentProductFindDependentProduct>,
    }
    #[derive(Deserialize, Debug)]
    pub struct FindDependentProductFindDependentProduct {
        pub uri: String,
        pub subject: FindDependentProductFindDependentProductSubject,
    }
    #[derive(Deserialize, Debug)]
    #[serde(tag = "__typename")]
    pub enum FindDependentProductFindDependentProductSubject {
        Package(FindDependentProductFindDependentProductSubjectOnPackage),
        Artifact,
    }
    #[derive(Deserialize, Debug)]
    pub struct FindDependentProductFindDependentProductSubjectOnPackage {
        #[serde(rename = "type")]
        pub type_: String,
        pub namespaces: Vec<FindDependentProductFindDependentProductSubjectOnPackageNamespaces>,
    }
    #[derive(Deserialize, Debug)]
    pub struct FindDependentProductFindDependentProductSubjectOnPackageNamespaces {
        pub namespace: String,
        pub names: Vec<FindDependentProductFindDependentProductSubjectOnPackageNamespacesNames>,
    }
    #[derive(Deserialize, Debug)]
    pub struct FindDependentProductFindDependentProductSubjectOnPackageNamespacesNames {
        pub name: String,
        pub versions: Vec<FindDependentProductFindDependentProductSubjectOnPackageNamespacesNamesVersions>,
    }
    #[derive(Deserialize, Debug)]
    pub struct FindDependentProductFindDependentProductSubjectOnPackageNamespacesNamesVersions {
        pub id: ID,
        pub version: String,
        pub qualifiers: Vec<FindDependentProductFindDependentProductSubjectOnPackageNamespacesNamesVersionsQualifiers>,
        pub subpath: String,
    }
    #[derive(Deserialize, Debug)]
    pub struct FindDependentProductFindDependentProductSubjectOnPackageNamespacesNamesVersionsQualifiers {
        pub key: String,
        pub value: String,
    }
}
impl graphql_client::GraphQLQuery for FindDependentProduct {
    type Variables = find_dependent_product::Variables;
    type ResponseData = find_dependent_product::ResponseData;
    fn build_query(variables: Self::Variables) -> ::graphql_client::QueryBody<Self::Variables> {
        graphql_client::QueryBody {
            variables,
            query: find_dependent_product::QUERY,
            operation_name: find_dependent_product::OPERATION_NAME,
        }
    }
}
