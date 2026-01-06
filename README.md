# EasyCodeSign

A Ruby gem for signing and verifying Ruby gems and ZIP files using hardware security tokens (HSM/smart cards). Currently supports SafeNet eToken with plans for additional providers.

## Features

- **Sign Ruby gems** (.gem) - Creates PKCS#7 signatures compatible with `gem cert`
- **Sign ZIP archives** (.zip, .jar, .apk, .war, .ear) - JAR-style signing with META-INF manifest
- **Hardware token support** - SafeNet eToken via PKCS#11 (extensible for other HSMs)
- **RFC 3161 timestamping** - Proves signature existed at a specific time
- **Full verification** - Signature, certificate chain, trust, and timestamp validation
- **Certificate revocation checking** - OCSP and CRL support
- **Command-line interface** - Easy-to-use CLI for signing and verification

## Installation

Add to your Gemfile:

```ruby
gem 'easy_code_sign'
```

Or install directly:

```bash
gem install easy_code_sign
```

### Prerequisites

- Ruby 3.2+
- SafeNet eToken drivers and PKCS#11 library installed
- Hardware token with code signing certificate

## Command-Line Usage

### Sign a file

```bash
# Basic signing (will prompt for PIN securely)
easysign sign my_gem-1.0.0.gem

# Sign with timestamp
easysign sign my_gem-1.0.0.gem --timestamp --tsa http://timestamp.digicert.com

# Sign with custom output path
easysign sign archive.zip --output signed_archive.zip

# Use specific PKCS#11 library
easysign sign my_gem.gem --library /path/to/libeToken.dylib
```

> **Security Note:** The PIN is always entered interactively via a secure prompt.
> It is never passed as a command-line argument to prevent exposure in shell
> history, process listings, or log files.

### Verify a signature

```bash
# Basic verification
easysign verify signed.gem

# Output as JSON
easysign verify signed.gem --json

# Use custom trust store
easysign verify signed.gem --trust-store /path/to/ca-certs/
```

### List available tokens

```bash
easysign list-slots
```

### Show signature information

```bash
easysign info signed.gem
```

## Ruby API

### Configuration

```ruby
require 'easy_code_sign'

EasyCodeSign.configure do |config|
  # Token provider (:safenet is currently supported)
  config.provider = :safenet

  # Path to PKCS#11 library (auto-detected if not specified)
  config.pkcs11_library = '/usr/local/lib/libeToken.dylib'

  # Token slot index (default: 0)
  config.slot_index = 0

  # Timestamp authority URL (optional)
  config.timestamp_authority = 'http://timestamp.digicert.com'

  # Hash algorithm for timestamps (default: :sha256)
  config.timestamp_hash_algorithm = :sha256

  # Require timestamp for all signatures (default: false)
  config.require_timestamp = false

  # Check certificate revocation during verification (default: true)
  config.check_revocation = true

  # Network timeout in seconds (default: 30)
  config.network_timeout = 30

  # Custom trust store path for verification (optional)
  config.trust_store_path = '/path/to/custom/ca-certs'

  # PIN callback for interactive PIN entry
  config.pin_callback = ->(slot_info) {
    print "Enter PIN for #{slot_info[:slot_index]}: "
    $stdin.noecho(&:gets).chomp
  }
end
```

### Signing

```ruby
# Sign a gem
result = EasyCodeSign.sign('my_gem-1.0.0.gem', pin: '1234')
puts "Signed: #{result.file_path}"
puts "Signer: #{result.signer_name}"

# Sign with timestamp
result = EasyCodeSign.sign('my_gem-1.0.0.gem',
  pin: '1234',
  timestamp: true
)
puts "Timestamp: #{result.timestamp}"

# Sign with custom output path
result = EasyCodeSign.sign('archive.zip',
  pin: '1234',
  output_path: 'signed_archive.zip',
  algorithm: :sha256_rsa
)

# Batch signing (single token session)
signer = EasyCodeSign.signer
results = signer.sign_batch(
  ['gem1.gem', 'gem2.gem', 'archive.zip'],
  pin: '1234'
)
```

### Verification

```ruby
# Verify a signed file
result = EasyCodeSign.verify('signed.gem')

if result.valid?
  puts "Signature is valid!"
  puts "Signed by: #{result.signer_name}"
  puts "Organization: #{result.signer_organization}"

  if result.timestamped?
    puts "Timestamp: #{result.timestamp}"
    puts "TSA: #{result.timestamp_authority}"
  end
else
  puts "Verification failed:"
  result.errors.each { |e| puts "  - #{e}" }
end

# Detailed verification status
puts "Signature valid: #{result.signature_valid?}"
puts "Integrity valid: #{result.integrity_valid?}"
puts "Certificate valid: #{result.certificate_valid?}"
puts "Chain valid: #{result.chain_valid?}"
puts "Trusted: #{result.trusted?}"

# Get full result as hash
puts result.to_h

# Use custom trust store
trust_store = EasyCodeSign::Verification::TrustStore.new
trust_store.add_file('/path/to/custom_ca.pem')
result = EasyCodeSign.verify('signed.gem', trust_store: trust_store)

# Batch verification
verifier = EasyCodeSign.verifier
results = verifier.verify_batch(['file1.gem', 'file2.zip'])
results.each do |path, result|
  puts "#{path}: #{result.valid? ? 'VALID' : 'INVALID'}"
end
```

### Working with Tokens

```ruby
# List available token slots
slots = EasyCodeSign.list_slots
slots.each do |slot|
  puts "Slot #{slot[:index]}: #{slot[:token_label]}"
  puts "  Serial: #{slot[:serial]}"
end

# Direct provider access
provider = EasyCodeSign.provider
provider.with_session(pin: '1234') do |session|
  cert = session.certificate
  puts "Certificate: #{cert.subject}"
  puts "Expires: #{cert.not_after}"

  chain = session.certificate_chain
  puts "Chain length: #{chain.length}"
end
```

## Supported Timestamp Authorities

Common free TSA endpoints:

| Provider | URL |
|----------|-----|
| DigiCert | `http://timestamp.digicert.com` |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` |
| Sectigo | `http://timestamp.sectigo.com` |
| SSL.com | `http://ts.ssl.com` |

## Error Handling

```ruby
begin
  EasyCodeSign.sign('file.gem', pin: '1234')
rescue EasyCodeSign::TokenNotFoundError
  puts "Hardware token not connected"
rescue EasyCodeSign::PinError => e
  puts "PIN error: #{e.message}"
  puts "Retries remaining: #{e.retries_remaining}" if e.retries_remaining
rescue EasyCodeSign::TokenLockedError
  puts "Token is locked - contact your administrator"
rescue EasyCodeSign::TimestampAuthorityError => e
  puts "Timestamp failed: #{e.message}"
  puts "HTTP status: #{e.http_status}" if e.http_status
rescue EasyCodeSign::InvalidFileError => e
  puts "Invalid file: #{e.message}"
rescue EasyCodeSign::Error => e
  puts "Signing error: #{e.message}"
end
```

## Architecture

```
EasyCodeSign
├── Providers           # Hardware token abstraction
│   ├── Base            # Abstract provider interface
│   ├── Pkcs11Base      # Shared PKCS#11 functionality
│   └── Safenet         # SafeNet eToken implementation
├── Signable            # File type handlers
│   ├── Base            # Abstract signable interface
│   ├── GemFile         # Ruby gem signing
│   └── ZipFile         # JAR-style ZIP signing
├── Timestamp           # RFC 3161 timestamping
│   ├── Client          # TSA HTTP client
│   ├── Request         # TimeStampReq builder
│   ├── Response        # TimeStampResp parser
│   └── Verifier        # Timestamp verification
├── Verification        # Signature verification
│   ├── Result          # Verification result
│   ├── TrustStore      # CA certificate management
│   ├── CertificateChain# Chain validation
│   └── SignatureChecker# Cryptographic verification
├── Signer              # Signing orchestrator
├── Verifier            # Verification orchestrator
└── CLI                 # Command-line interface
```

## Security Considerations

- **PINs are never passed as CLI arguments** - Always entered via secure interactive prompt
- **PINs are never logged or stored** - Use `pin_callback` for programmatic secure entry
- **Hardware tokens protect private keys** - Keys never leave the HSM
- **Timestamps provide non-repudiation** - Signatures remain valid after certificate expiry
- **Certificate revocation is checked** - OCSP (real-time) with CRL fallback
- **System CA store is used by default** - Custom trust stores supported

## Development

```bash
# Install dependencies
bin/setup

# Run tests
bundle exec rake test

# Run linter
bundle exec rubocop

# Interactive console
bin/console

# Install locally
bundle exec rake install
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/mpantel/easy_code_sign.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
