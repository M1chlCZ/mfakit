# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `OTPAuthURI` returns an `otpauth://totp/` provisioning URI for authenticator apps. The label carries the issuer and account, the secret parameter is base32 without padding, and the algorithm, digits, and period follow the package parameters. QR rendering stays with the caller.
