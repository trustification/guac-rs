# Changelog

## [Unreleased](https://github.com/trustification/guac-rs/compare/v0.1.0...HEAD) (2024-02-09)

### Features

* find product based on package
([7596de7](https://github.com/trustification/guac-rs/commit/7596de7cfafb59255bb6f629fdc9857c4e620fb9))
* implement find_vulnerability_by_sbom_uri query
([fb21d4f](https://github.com/trustification/guac-rs/commit/fb21d4fae116d88d1b0076cfdefb58cc472678d7))
* add pagination to the find_vulnerability query
([1a5f860](https://github.com/trustification/guac-rs/commit/1a5f860197776081cb91c17fe6b3f63cc3cc45c1))
* process CertifyVuln in result
([cf327c8](https://github.com/trustification/guac-rs/commit/cf327c88412cdf0aa14a1e1b56c693187aab345d))
* add vulnerabilities query
([b0b3d5c](https://github.com/trustification/guac-rs/commit/b0b3d5c0d5e40408886650418d453ab716b9d1f1))
* implement product_by_cve api
([6d11cae](https://github.com/trustification/guac-rs/commit/6d11cae23d765952665b3db61ffe28357b93ccb8))
* add support for document content encoding
([1d952f7](https://github.com/trustification/guac-rs/commit/1d952f71af908c43fb550ad2d450f68561f31aae))
* use more refined errors
([f74e28a](https://github.com/trustification/guac-rs/commit/f74e28a6fb6881c0ecf3701efcc8e3067f0cb2d6))

### Fixes

* add certify_vulns to the find_vulnerability_statuses function
([a36282f](https://github.com/trustification/guac-rs/commit/a36282f462c80b79b22547340f0d5416d1a46a44))
* find_vulnerability_statuses to use certify vex directly
([62c0ebf](https://github.com/trustification/guac-rs/commit/62c0ebffc24c944106a2894d062483fdeea68aba))
* find_vulnerability should return only affected statements
([947e418](https://github.com/trustification/guac-rs/commit/947e418393c28d4e65c10fda478513670a70a5e7))
* namespaces in purls
([12972f8](https://github.com/trustification/guac-rs/commit/12972f840f8c895fcde23713df9d4d4ae12276c6))
* handle error
([76053d0](https://github.com/trustification/guac-rs/commit/76053d07948cf557b9d978ef39d574ed1562cf70))
* re-enable cli query depenency commands
([e6b39b4](https://github.com/trustification/guac-rs/commit/e6b39b4cc2580821e751a45628b5babe1c30d7df))
* use tmp exporter build with valid guac dependency
([cf7932e](https://github.com/trustification/guac-rs/commit/cf7932e6d836c319872ff5ded03affea918382d1))
* upgrade package query according to the new schema
([b8f095a](https://github.com/trustification/guac-rs/commit/b8f095a087194ef34d494a2da967e45b0ab73f30))

### Other

* update dependencies
([e906321](https://github.com/trustification/guac-rs/commit/e906321a1f77c5e7a70a0102f7d6048336c76926))
* adds contributing guide
([619c8f5](https://github.com/trustification/guac-rs/commit/619c8f516e5c0a789398dc60d3b2a0b229781768))
* removes remaining unused dependencies
([1ca4342](https://github.com/trustification/guac-rs/commit/1ca4342551301f472284eb8a44d99529e7ab7d4e))
* removes openvex dependency
([8a4ac5c](https://github.com/trustification/guac-rs/commit/8a4ac5c892cd736ededb9ff083e65d7f68d0a1d9))
* fix remaining clippy warnings
([aa57311](https://github.com/trustification/guac-rs/commit/aa5731132074ec384b8322a40aca83db163053b6))
* fix some clippy warnings in tests
([2324978](https://github.com/trustification/guac-rs/commit/232497833e1e4837b57445d63273d0526e3adf46))
* using same toolchain as trustification
([3e804a3](https://github.com/trustification/guac-rs/commit/3e804a3cd26a2c37b21274357736de606cc647c9))
* markdown linting
([0c20a81](https://github.com/trustification/guac-rs/commit/0c20a81fcc405dfdf7026f2ca0227f0c22c933f7))
* allow providing an existing client
([561931b](https://github.com/trustification/guac-rs/commit/561931b314e4ed486ef0372c6afe9f6b83fa3dd4))
* move spog queries to semantic client
([31f3831](https://github.com/trustification/guac-rs/commit/31f383171f2115f7bd18949d78ae7267381037ec))
* update graphql schema
([1ee716e](https://github.com/trustification/guac-rs/commit/1ee716ea76557d613ffbdf5ca50783473c32bd68))
* enable tests in workflows
([68e2c34](https://github.com/trustification/guac-rs/commit/68e2c34147cf55227815783480d92c6ff0ffd96a))
* code formatting
([0fa724a](https://github.com/trustification/guac-rs/commit/0fa724aaf53729dc2e8edb5af5fa0b5d41ed4e2a))
* remove env_logger
([bcee96a](https://github.com/trustification/guac-rs/commit/bcee96a62e3e1b62a213a115cb500d728800b1d1))

### Documentation

* basic local tests docs
([81c5a4b](https://github.com/trustification/guac-rs/commit/81c5a4bb795e7f0afb34fbe0a0fbd05e5437350d))
* add guac development notes
([9e24149](https://github.com/trustification/guac-rs/commit/9e241496035e6548499d2518ee61f94816a61867))

## v0.1.0 (2023-07-10)

### Features

* implement Debug, PartialEq, Eq
([d7c36f8](https://github.com/trustification/guac-rs/commit/d7c36f8936e2cb15da9de75b3b52be80fb1854a1))
* add S3 collector
([9990e07](https://github.com/trustification/guac-rs/commit/9990e07ee12128e1cedf3eda6ad73615e2077cfa))
* Add FileCollector
([23c76be](https://github.com/trustification/guac-rs/commit/23c76bed4a4d7723f79e4fe590cb880676cc67ce))
* Implement Collector abstractions
([eb4037f](https://github.com/trustification/guac-rs/commit/eb4037feaf734311c597bb01cc0ee602313f744a))
* provide emitter abstraction
([316682d](https://github.com/trustification/guac-rs/commit/316682d001235554ee38daf931ff5214a3530511))
* add basic example of implementing collector
([b4e1d15](https://github.com/trustification/guac-rs/commit/b4e1d15b012912fd3f07b9a248a7ba44b7825e50))

### Fixes

* handle vex output for vulnerabilities
([e5310f6](https://github.com/trustification/guac-rs/commit/e5310f6a89a45e980bb0e0cf6416fab286483040))
* get dependencies query
([795d78b](https://github.com/trustification/guac-rs/commit/795d78bae5303b493ab77be85b011f1075efb958))

### Other

* prep for initial release
([a643316](https://github.com/trustification/guac-rs/commit/a64331682d0cac81bd07a44c7b657cae48adfb39))
* graphql config for intellij development
([937c221](https://github.com/trustification/guac-rs/commit/937c22161a8d29296ec19667577f2cb532ccf9f5))
* ignore intellij files
([9a506a0](https://github.com/trustification/guac-rs/commit/9a506a06338145e1f2d70ab53644da6e1f60e55a))
* refactor file collect command
([4a40c48](https://github.com/trustification/guac-rs/commit/4a40c48e0e5338355f9b4adb7d0e550e56075872))
* refactor code to support both query and collect commands from CLI
([a8541be](https://github.com/trustification/guac-rs/commit/a8541be7636a09a70d392bcba47ae4e44e341c15))
* move collector abstractions to the new module
([876af20](https://github.com/trustification/guac-rs/commit/876af20a795791c48d52f4a4355b81c85c3d2d70))
* move graphql api client to separate module
([12531e2](https://github.com/trustification/guac-rs/commit/12531e20c230090713c1c1809a4c46bb1766e508))
