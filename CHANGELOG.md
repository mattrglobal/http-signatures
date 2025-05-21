# [4.2.0](https://github.com/mattrglobal/http-signatures/compare/v4.1.0...v4.2.0) (2025-05-21)

* Upgrade dependencies to fix vulnerabilities


## [4.1.1](https://github.com/mattrglobal/http-signatures/compare/v4.1.0...v4.1.1) (2024-04-09)

* Upgrade dependencies to fix vulnerabilities


## [4.1.0](https://github.com/mattrglobal/http-signatures/compare/v4.0.1...v4.1.0) (2023-10-03)


### Bug Fixes

* Correct import paths, verifyRequest accepts verifyExpiry argument ([#49](https://github.com/mattrglobal/http-signatures/issues/49)) ([301ff26](https://github.com/mattrglobal/http-signatures/commit/301ff269bfcab22916a42ab1f268ac4fe613f2fa))



## [4.0.1](https://github.com/mattrglobal/http-signatures/compare/v4.0.0...v4.0.1) (2022-10-24)

### Notes

* Add missing logo svg only

## [4.0.0](https://github.com/mattrglobal/http-signatures/compare/v3.0.2...v4.0.0) (2022-10-21)


### Features

* add reasons for verification failing, allow skipping expiry verification ([#45](https://github.com/mattrglobal/http-signatures/issues/45)) ([6b1ca8a](https://github.com/mattrglobal/http-signatures/commit/6b1ca8aead8992080a573c26005b0601976c3517))


### BREAKING CHANGES

* verifySignatureHeader and verifyRequest response structure changed


## 3.0.2 (2022-10-11)


### Bug Fixes

* **deps:** move structured-headers to direct dependency ([#43](https://github.com/mattrglobal/http-signatures/issues/43)) ([3691800](https://github.com/mattrglobal/http-signatures/commit/36918009892d4982d0a292bb80921cdec95760a4))



## 3.0.0 (2022-10-11)

### Breaking Changes

* Apply the latest [HTTP Signatures IETF specification](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html)
* Make library open-source
