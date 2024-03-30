## [Unreleased]

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
