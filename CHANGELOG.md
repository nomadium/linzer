## [Unreleased]

- Fix a few bugs when signing rack responses.

- Add Linzer.signature_base method.

- Add initial support for JWS algorithms. See Linzer::JWS module for more details.
  In this initial preview, only EdDSA algorithm (Ed25519) is supported).

- Add a simple integration test to verify signatures on HTTP responses.

## [0.7.2] - 2025-05-21

- Add a few integration tests against CloudFlare test server.

- Fix bug when accessing headers in http adapter classes.
  Pull request [#14](https://github.com/nomadium/linzer/pull/14)
  by [oneiros](https://github.com/oneiros).

## [0.7.1] - 2025-05-18

- Introduce specific exception classes for message signing errors
  and signature verification exceptions (i.e. Linzer::SigningError
  and Linzer::VerifyError)

- Fix bug in Linzer::HTTP client that prevented it from working with https URLs.

## [0.7.0] - 2025-05-17

(No changes since the last beta release, this new stable release just
bundles all the features/changes introduced during 0.7.0 beta releases) 

- Introduce Rack::Auth::Signature middleware.

- Refactor and improve Rack::Auth::Signature code organization.

- Do not expose secret material on HMAC SHA-256 key when #inspect method is used.

- Update Rack::Auth::Signature configuration file options.

- Validate and test Rack::Auth::Signature with example Rails and Sinatra apps.

- Refactor to improve Linzer APIs and streamline its usage along with different
  HTTP libraries. (Issues [#6](https://github.com/nomadium/linzer/issues/6) and
  [#11](https://github.com/nomadium/linzer/issues/11))

- Provide integration with http.rb gem to allow signing outgoing HTTP requests.

- Add simple HTTP client module.

## [0.7.0.beta4] - 2025-05-17

- Provide integration with http.rb gem to allow signing outgoing HTTP requests.
- Add simple HTTP client module.

## [0.7.0.beta3] - 2025-05-06 (aka the ["MiniDebConf Hamburg 2025"](https://wiki.debian.org/DebianEvents/de/2025/MiniDebConfHamburg) release)

- Refactor to improve Linzer APIs and streamline its usage along with different
  HTTP libraries.

## [0.7.0.beta2] - 2025-04-13

- Refactor and improve Rack::Auth::Signature code organization.
- Do not expose secret material on HMAC SHA-256 key when #inspect method is used.
- Update Rack::Auth::Signature configuration file options.
- Validate and test Rack::Auth::Signature with example Rails and Sinatra apps.

## [0.7.0.beta1] - 2025-04-12

- Introduce Rack::Auth::Signature middleware.

## [0.6.5] - 2025-04-09

- Add support for RSA (RSASSA-PKCS1-V1_5) and improve RSASSA-PSS handling.
  Pull request [#10](https://github.com/nomadium/linzer/pull/10)
  by [oneiros](https://github.com/oneiros).

## [0.6.4] - 2025-04-04

- Allow validating the `created` parameter to mitigate the
  risk of replay attacks.
  Pull request [#8](https://github.com/nomadium/linzer/pull/8)
  by [oneiros](https://github.com/oneiros).

## [0.6.3] - 2025-03-29

- Parse signature structured fields values as ASCII string.

## [0.6.2] - 2024-12-10

- Remove dependency on ed25519 gem. Pull request
  [#5](https://github.com/nomadium/linzer/pull/5) by
  [oneiros](https://github.com/oneiros).

- Run unit tests against Ruby 3.4.

## [0.6.1] - 2024-12-02

- Add more validation checks on HTTP field component identifiers and parameters.

- Relax rack version requirements. Pull request
  [#4](https://github.com/nomadium/linzer/pull/4) by
  [oneiros](https://github.com/oneiros).

- Update uri dependency to the latest version. Pull request
  [#3](https://github.com/nomadium/linzer/pull/3) by
  [oneiros](https://github.com/oneiros).

## [0.6.0] - 2024-04-06

- Support parameters on HTTP field component identifiers.

- Add a work-around for failed unit-tests in ruby HEAD CI jobs.

- Set up simplecov and improve unit-tests coverage.

## [0.5.2] - 2024-04-02

- Make all unit tests pass on Ruby 3.0:
  * Set minimum required version on openssl and uri gems.
- Small refactor on ECDSA module.

## [0.5.1] - 2024-04-01

- Add support for additional derived components:
  @target-uri, @scheme, @request-target, @query and @query-param.

## [0.5.0] - 2024-03-30

- Build Linzer::Message instances from Rack request and response objects
  instead of unspecified/ad-hoc hashes with HTTP request and
  response parameters.

- Update README examples.

## [0.4.1] - 2024-03-25

- Fix one-off error on ECDSA P-256 and P-384 curve signature generation.
  In some cases, an invalid signature of 63 or 95 bytes could be generated.

## [0.4.0] - 2024-03-16

- Add support for capitalized HTTP header names.

## [0.3.2] - 2024-03-16

- Force signature component name strings to be encoded as ASCII.
  Otherwise in some scenarios, this could to signature verification errors
  for valid signatures.

## [0.3.1] - 2024-03-02

- Fix incorrect signing and verifying for ECDSA P-256 and P-384 curves.

## [0.3.0] - 2024-02-28

- Add support for the following algorithms: Ed25519, HMAC-SHA256 and
  ECDSA (P-256 and P-384 curves).

## [0.2.0] - 2024-02-23

- Add signature signing functionality. RSASSA-PSS using SHA-512 is still the only
  supported algorithm.

## [0.1.0] - 2024-02-18

- Initial release
- It barely passes unit tests to verify signatures with RSASSA-PSS using SHA-512.
