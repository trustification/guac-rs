# Guac Rust library

This library provides for Guac GraphQL API and a command-line interface (CLI)  that uses this this library to query Guac.


## Prerequisites

In order to use this library and CLI, you need to have a running Guac instance (and preferably ingest some data into it).
Following [Guac Docker Compose guide](https://github.com/guacsec/guac/blob/main/docs/Compose.md) might be the easiest way to 
get you started.

## Install

To install CLI, run

```
cargo install --path=cli
```

from the root directory.

## Use

The following are examples of commands that CLI (and thus the library as well) are supporting.

### Get dependencies

Returns purls of all known dependencies of the provided purl.

```
$ guac dependencies pkg:maven/io.vertx/vertx-web@4.3.7
[
  "pkg:maven/io.vertx/vertx-web-common@4.3.7",
  "pkg:maven/io.vertx/vertx-auth-common@4.3.7",
  "pkg:maven/io.vertx/vertx-bridge-common@4.3.7",
  "pkg:maven/io.vertx/vertx-core@4.3.7"
]
```

### Get dependents

Returns purls of all known dependents for the provided purl.

```
$ guac dependents pkg:maven/io.vertx/vertx-web@4.3.7
[
  "pkg:maven/io.seedwing/seedwing-java-example@1.0.0-SNAPSHOT?type=jar",
  "pkg:maven/io.quarkus.resteasy.reactive/resteasy-reactive-vertx@2.16.2.Final?type=jar",
  "pkg:maven/io.quarkus/quarkus-vertx-http@2.16.2.Final?type=jar",
  "pkg:maven/io.quarkus/quarkus-vertx-http-dev-console-runtime-spi@2.16.2.Final?type=jar",
  "pkg:maven/io.smallrye.reactive/smallrye-mutiny-vertx-web@2.30.1?type=jar"
]
```

### Get Vulnerabilities

Returns list of all known vulnerabilities for the provided purl

```
$ guac vulnerabilities pkg:rpm/redhat/openssl@1.1.1k-7.el8_6
[
  {
    "cve": "cve-2023-0286",
    "ghsa": null,
    "no_vuln": null,
    "osv": null,
    "packages": [
      "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6?arch=x86_64&epoch=1"
    ]
  }
]
```

### Get Packages

Returns list of all versions for the given package purl

```
$ guac packages pkg:maven/io.vertx/vertx-web
[
  "pkg:maven/io.vertx/vertx-web@4.3.7?type=jar",
  "pkg:maven/io.vertx/vertx-web@4.3.4.redhat-00007?type=jar"
]
```

## Contribute

### Update schema

```
cargo install graphql_client_cli --force
graphql-client introspect-schema http://localhost:8080/query > lib/src/graphql/schema.json
```
