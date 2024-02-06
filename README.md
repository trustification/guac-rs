# Guac Rust library

[![Rust](https://github.com/trustification/guac-rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/trustification/guac-rs/actions/workflows/rust.yml)

This library provides toolkit for working with [Guac](https://guac.sh) from Rust. It can be used for querying data using GraphQL API and ingesting data with collectors. It also contains a command-line interface (CLI) that exposes query API and collectors.

## Prerequisites

In order to use this library and CLI, you need to have a running Guac instance (and preferably ingest some data into it).
Following [Guac Docker Compose guide](https://github.com/guacsec/guac/blob/main/docs/Compose.md) might be the easiest way to
get you started.

## Install

To install CLI, run

```shell
cargo install --path=cli
```

from the root directory.

## Use

Once the CLI is installed, you can use it to query and ingest Guac data.

### Queries

The following are examples of query commands that CLI (and thus the library as well) are supporting.

#### Get dependencies

Returns purls of all known dependencies of the provided purl.

```shell
$ guac query dependencies pkg:maven/io.vertx/vertx-web@4.3.7
[
  "pkg:maven/io.vertx/vertx-web-common@4.3.7",
  "pkg:maven/io.vertx/vertx-auth-common@4.3.7",
  "pkg:maven/io.vertx/vertx-bridge-common@4.3.7",
  "pkg:maven/io.vertx/vertx-core@4.3.7"
]
```

#### Get dependents

Returns purls of all known dependents for the provided purl.

```shell
$ guac query dependents pkg:maven/io.vertx/vertx-web@4.3.7
[
  "pkg:maven/io.seedwing/seedwing-java-example@1.0.0-SNAPSHOT?type=jar",
  "pkg:maven/io.quarkus.resteasy.reactive/resteasy-reactive-vertx@2.16.2.Final?type=jar",
  "pkg:maven/io.quarkus/quarkus-vertx-http@2.16.2.Final?type=jar",
  "pkg:maven/io.quarkus/quarkus-vertx-http-dev-console-runtime-spi@2.16.2.Final?type=jar",
  "pkg:maven/io.smallrye.reactive/smallrye-mutiny-vertx-web@2.30.1?type=jar"
]
```

#### Get Vulnerabilities

Returns list of all known vulnerabilities for the provided purl

```shell
$ guac query vulnerabilities pkg:rpm/redhat/openssl@1.1.1k-7.el8_6
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

#### Get Packages

Returns list of all versions for the given package purl

```shell
$ guac query packages pkg:maven/io.vertx/vertx-web
[
  "pkg:maven/io.vertx/vertx-web@4.3.7?type=jar",
  "pkg:maven/io.vertx/vertx-web@4.3.4.redhat-00007?type=jar"
]
```

### Collectors

#### S3

The S3 collector is implemented as part of the [Trustification](https://docs.trustification.dev/) project. For more
documentation take a look at [https://github.com/trustification/trustification/tree/main/exporter].

If you wish to run it locally with just Bombastic/Vexination APIs in combination with Minio and Kafka, run

``` shell
cd example/compose
docker-compose -f compose.yaml -f compose-trustification.yaml -f compose-guac.yaml up
```

Then you can run the collector like

```shell
RUST_LOG=debug cargo run --bin guac collect s3 --storage-bucket bombastic  --devmode
```

Now, you can ingest your SBOMs, like

```shell
curl -X POST --json @example/seedwing-java-example.bom "http://localhost:8082/api/v1/sbom?id=my-sbom"
```

And use Guac to explore data

```shell
open http://localhost:8084
```

#### File

The file collector can at the moment ingest only individual files, like

```shell
cargo run --bin guac collect file example/seedwing-java-example.bom
```

## Contribute

See [contributing guide](./CONTRIBUTING.md).

### Update schema

```shell
cargo install graphql_client_cli --force
graphql-client introspect-schema http://localhost:8080/query > lib/src/client/intrinsic/schema.json
```
