# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

EasyCodeSign is a Ruby gem for signing and verifying Ruby gems, ZIP archives, and PDF documents using hardware security tokens (HSM/smart cards) via PKCS#11. Currently supports SafeNet eToken.

- Ruby 3.2+ required
- Entry point: `lib/easy_code_sign.rb`
- CLI executable: `exe/easysign` (Thor-based)
- Version in `lib/easy_code_sign/version.rb`

## Commands

```bash
bundle exec rake test          # Run all tests
bundle exec rake rubocop       # Run linter
bundle exec rake               # Run both (default task)
bundle exec ruby -Ilib:test test/signable_test.rb                    # Run single test file
bundle exec ruby -Ilib:test test/signable_test.rb --name test_name   # Run single test method
bin/console                    # Interactive console (IRB with gem loaded)
bundle exec rake install       # Install gem locally
```

## Code Style

- **Minitest** for testing (not RSpec, despite RSpec being in the Gemfile)
- All tests inherit from `EasyCodeSignTest` (defined in `test/test_helper.rb`), which resets configuration/provider state between tests
- **Double quotes** enforced for strings and interpolation (`.rubocop.yml`)
- `frozen_string_literal: true` at top of all Ruby files

## Architecture

Three-layer design with orchestrators delegating to subsystems:

**Orchestrators** (`signer.rb`, `verifier.rb`) — coordinate the full signing/verification workflow. `EasyCodeSign.sign()` and `EasyCodeSign.verify()` are the primary API entry points.

**Provider pattern** (`providers/`) — abstracts hardware token communication. `Base` → `Pkcs11Base` → `Safenet`. New HSM support = new provider class inheriting `Pkcs11Base`. Providers manage PKCS#11 sessions, PIN auth, and delegate signing to the hardware token.

**Signable pattern** (`signable/`) — each file type has its own signing/verification strategy:
- `GemFile` — PKCS#7 detached signatures on data.tar.gz, metadata.gz, checksums.yaml.gz
- `ZipFile` — JAR-style META-INF/ manifest signing (MANIFEST.MF → CERT.SF → CERT.RSA)
- `PdfFile` — HexaPDF ByteRange-based signing with deferred signing callback

**Verification subsystem** (`verification/`) — `Result` carries detailed status (signature, integrity, chain, trust, timestamp, revocation). `TrustStore` wraps OpenSSL CA store. `CertificateChain` does OCSP/CRL revocation checking. `SignatureChecker` verifies PKCS#7 signatures.

**Timestamp subsystem** (`timestamp/`) — RFC 3161 client/request/response/verifier for timestamping signatures via TSA servers.

**Key flow**: `EasyCodeSign.sign()` → `Signer` → detects file type → creates `Signable` → opens provider session → `signable.content_to_sign` → `provider.sign(data)` → optionally requests timestamp → `signable.apply_signature()`.

## Error Hierarchy

All errors inherit from `EasyCodeSign::Error`. Granular subclasses in `errors.rb` cover token, signing, verification, timestamp, and PDF errors. Some carry metadata (e.g., `PinError#retries_remaining`, `Pkcs11Error#pkcs11_error_code`, `TimestampAuthorityError#http_status`).

## Adding a New Signable File Type

1. Create `lib/easy_code_sign/signable/new_type.rb` inheriting `Signable::Base`
2. Implement: `prepare_for_signing`, `content_to_sign`, `apply_signature`, `extract_signature`, `signed?`
3. Register the extension in `EasyCodeSign.signable_for` (in `lib/easy_code_sign.rb`)
4. Add verification support in `Verifier`
5. Add CLI options if needed in `cli.rb`
