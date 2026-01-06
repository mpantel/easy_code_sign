# EasyCodeSign

A Ruby gem for signing and verifying zip files and Ruby gems using hardware token-based signatures (HSM/smart cards).

## Project Overview

**Purpose**: Provide a clean, extensible interface for code signing and verification operations using hardware security tokens, starting with SafeNet eToken support.

**Key Features**:
- Sign Ruby gems (.gem files)
- Sign ZIP archives
- **Verify signatures on signed artifacts**
- Hardware token integration via PKCS#11
- **RFC 3161 timestamp authority support**
- Extensible provider architecture for future token types

## Architecture

```
lib/
├── easy_code_sign.rb              # Main entry point, configuration
├── easy_code_sign/
│   ├── version.rb                 # Gem version
│   ├── configuration.rb           # Global configuration
│   ├── signer.rb                  # Main signing orchestrator
│   ├── verifier.rb                # Signature verification orchestrator
│   ├── errors.rb                  # Custom error classes
│   │
│   ├── providers/                 # Token provider abstraction
│   │   ├── base.rb                # Abstract base provider
│   │   ├── safenet.rb             # SafeNet eToken implementation
│   │   └── pkcs11_base.rb         # Shared PKCS#11 functionality
│   │
│   ├── signable/                  # Signable file type handlers
│   │   ├── base.rb                # Abstract base for signable types
│   │   ├── gem_file.rb            # Ruby gem signing logic
│   │   └── zip_file.rb            # ZIP archive signing logic
│   │
│   ├── verification/              # Verification subsystem
│   │   ├── result.rb              # Verification result object
│   │   ├── certificate_chain.rb   # Certificate chain validation
│   │   ├── signature_checker.rb   # Cryptographic signature validation
│   │   └── trust_store.rb         # Trusted certificate management
│   │
│   ├── timestamp/                 # Timestamping support
│   │   ├── client.rb              # TSA client (RFC 3161)
│   │   ├── response.rb            # Timestamp response handling
│   │   └── verifier.rb            # Timestamp verification
│   │
│   └── cli.rb                     # Command-line interface
```

## Implementation Plan

### Phase 1: Foundation
1. [ ] Initialize gem structure with bundler
2. [ ] Set up configuration system
3. [ ] Define error hierarchy
4. [ ] Create abstract provider interface

### Phase 2: PKCS#11 Integration
5. [ ] Integrate pkcs11 gem for hardware token communication
6. [ ] Implement SafeNet provider
7. [ ] Handle PIN entry securely
8. [ ] Support certificate chain retrieval from token

### Phase 3: Signing Operations
9. [ ] Implement gem file signing (compatible with `gem cert`)
10. [ ] Implement ZIP signing (detached signature + manifest)
11. [ ] Create unified Signer interface

### Phase 4: Timestamping
12. [ ] Implement RFC 3161 timestamp client
13. [ ] Support configurable TSA URLs (DigiCert, GlobalSign, etc.)
14. [ ] Embed timestamps in signatures
15. [ ] Handle TSA authentication (if required)

### Phase 5: Verification
16. [ ] Create VerificationResult class with detailed status
17. [ ] Implement signature verification for gems
18. [ ] Implement signature verification for ZIP files
19. [ ] Certificate chain validation (root → intermediate → leaf)
20. [ ] Certificate revocation checking (CRL/OCSP)
21. [ ] Timestamp verification and validation
22. [ ] Trust store management (system + custom trusted certs)

### Phase 6: CLI & Polish
23. [ ] Build CLI with Thor or OptionParser
24. [ ] Add comprehensive error messages
25. [ ] Documentation and examples

## Technical Decisions

### PKCS#11 Library
Use the `pkcs11` gem which provides Ruby bindings to PKCS#11 libraries. SafeNet tokens typically use:
- macOS: `/usr/local/lib/libeToken.dylib`
- Linux: `/usr/lib/libeToken.so`
- Windows: `eToken.dll`

### Signature Format
- **Ruby Gems**: Follow standard gem signing format (SHA256/SHA512 with RSA)
- **ZIP Files**: Use JAR-style signing with META-INF/SIGNATURE.SF manifest

### Timestamping (RFC 3161)
Timestamps prove signature existed at a specific time, allowing verification even after certificate expiry:
```ruby
EasyCodeSign.configure do |config|
  config.timestamp_authority = 'http://timestamp.digicert.com'
  config.timestamp_hash_algorithm = :sha256
end
```

Common TSA endpoints:
- DigiCert: `http://timestamp.digicert.com`
- GlobalSign: `http://timestamp.globalsign.com/tsa/r6advanced1`
- Sectigo: `http://timestamp.sectigo.com`

### Verification API
```ruby
# Verify a signed artifact
result = EasyCodeSign.verify('path/to/signed.gem')

result.valid?              # Overall validity
result.signature_valid?    # Cryptographic signature OK
result.certificate_valid?  # Certificate chain valid
result.timestamp_valid?    # Timestamp present and valid
result.trusted?            # Signing cert chains to trusted root
result.signer              # Certificate info of signer
result.timestamp           # Timestamp info (if present)
result.errors              # Array of validation errors
result.warnings            # Array of warnings (e.g., expiring cert)
```

### Provider Pattern
Extensible design allowing future providers:
```ruby
EasyCodeSign.configure do |config|
  config.provider = :safenet
  config.pkcs11_library = '/path/to/library'
end
```

## Dependencies

- `pkcs11` - PKCS#11 bindings
- `openssl` - Certificate/signature operations (stdlib)
- `zip` or `rubyzip` - ZIP manipulation
- `net-http` - TSA communication (stdlib)
- `thor` - CLI (optional)

## Development Guidelines

- Ruby 3.0+ required
- Use RSpec for testing
- Mock PKCS#11 operations in tests (SoftHSM2 for integration tests)
- Follow standard Ruby style (RuboCop)

## Security Considerations

- Never log or store PINs
- Clear sensitive memory when possible
- Support secure PIN entry callbacks
- Validate certificate chains before signing
- Validate TSA responses cryptographically
- Use HTTPS for TSA communication when available
- Check certificate revocation status during verification
