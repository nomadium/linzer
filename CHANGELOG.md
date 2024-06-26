## [Unreleased]

- Switch to pre-release starry version on ruby-head.
- Add more validation checks on HTTP field component identifiers and parameters.

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
