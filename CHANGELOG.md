# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **PDF Document Signing**
  - Sign PDF documents (.pdf) with PKCS#7 digital signatures
  - Visible signature annotations with customizable position (top-left, top-right, bottom-left, bottom-right)
  - Signature metadata (reason, location, contact info)
  - Page selection for signature placement
  - RFC 3161 timestamp embedding in PDF signatures
  - ByteRange-based signing for PDF incremental updates

- **PDF Verification**
  - Verify signed PDF documents
  - ByteRange integrity checking
  - Extract and display PDF signature metadata

- **CLI Enhancements for PDF**
  - `--visible-signature` - Add visible signature annotation
  - `--signature-page` - Select page for signature
  - `--signature-position` - Position preset (top_left, top_right, bottom_left, bottom_right)
  - `--signature-reason` - Reason for signing
  - `--signature-location` - Signing location

### Dependencies

- Added HexaPDF (~> 1.0) for PDF manipulation and signing

## [0.1.0] - 2025-01-06

### Added

- **Core Signing Functionality**
  - Sign Ruby gems (.gem) with PKCS#7 detached signatures compatible with `gem cert`
  - Sign ZIP archives (.zip, .jar, .apk, .war, .ear) using JAR-style signing with META-INF manifest
  - Batch signing support for multiple files in a single token session

- **Hardware Token Support**
  - SafeNet eToken integration via PKCS#11
  - Extensible provider architecture for future HSM support
  - Automatic PKCS#11 library detection on macOS, Linux, and Windows
  - Secure PIN entry via interactive prompt (never passed as CLI argument)
  - Token slot listing and management

- **RFC 3161 Timestamping**
  - Full RFC 3161 timestamp protocol support
  - Compatible with common TSAs (DigiCert, GlobalSign, Sectigo, SSL.com)
  - Timestamp verification with certificate chain validation
  - Configurable hash algorithms (SHA-256, SHA-384, SHA-512)

- **Signature Verification**
  - Cryptographic signature validation
  - File integrity checking (tamper detection)
  - Certificate validity and expiration checking
  - Certificate chain validation
  - Trust anchor verification using system CA store or custom trust stores
  - Timestamp validation for point-in-time verification
  - Certificate revocation checking (OCSP with CRL fallback)

- **Command-Line Interface**
  - `easysign sign` - Sign files with hardware token
  - `easysign verify` - Verify signed files with detailed output
  - `easysign list-slots` - List available token slots
  - `easysign info` - Display signature information
  - JSON output option for scripting and automation
  - Verbose and quiet modes

- **Ruby API**
  - Simple high-level API (`EasyCodeSign.sign`, `EasyCodeSign.verify`)
  - Comprehensive configuration system
  - Custom trust store support
  - PIN callback for programmatic secure PIN entry
  - Detailed result objects with structured error reporting

- **Error Handling**
  - 18 specific error types for clear diagnostics
  - Hierarchical error classes for flexible rescue
  - PIN retry tracking with lockout warnings
  - Network timeout handling for TSA requests

### Security

- PINs are never logged, stored, or passed as command-line arguments
- Secure interactive PIN prompt using `noecho` to prevent display
- Private keys never leave the hardware token
- Certificate revocation checking enabled by default

[0.1.0]: https://github.com/mpantel/easy_code_sign/releases/tag/v0.1.0
