# frozen_string_literal: true

require "test_helper"
require "tempfile"

class VerificationResultTest < Minitest::Test
  def test_initializes_with_default_values
    result = EasyCodeSign::Verification::Result.new

    refute result.valid?
    refute result.signature_valid?
    refute result.integrity_valid?
    refute result.certificate_valid?
    refute result.chain_valid?
    refute result.trusted?
    refute result.timestamped?
    assert_empty result.errors
    assert_empty result.warnings
  end

  def test_add_error
    result = EasyCodeSign::Verification::Result.new
    result.add_error("Test error")

    assert_includes result.errors, "Test error"
  end

  def test_add_warning
    result = EasyCodeSign::Verification::Result.new
    result.add_warning("Test warning")

    assert_includes result.warnings, "Test warning"
  end

  def test_certificate_expired_returns_true_for_expired_cert
    result = EasyCodeSign::Verification::Result.new

    cert = OpenSSL::X509::Certificate.new
    cert.not_before = Time.now - 86_400 * 365
    cert.not_after = Time.now - 86_400 # Expired yesterday

    result.signer_certificate = cert

    assert result.certificate_expired?
  end

  def test_certificate_expired_returns_false_for_valid_cert
    result = EasyCodeSign::Verification::Result.new

    cert = OpenSSL::X509::Certificate.new
    cert.not_before = Time.now - 86_400
    cert.not_after = Time.now + 86_400 * 365

    result.signer_certificate = cert

    refute result.certificate_expired?
  end

  def test_to_h_returns_hash
    result = EasyCodeSign::Verification::Result.new
    result.file_path = "/path/to/file.gem"
    result.file_type = :gem
    result.valid = true

    hash = result.to_h

    assert_equal "/path/to/file.gem", hash[:file_path]
    assert_equal :gem, hash[:file_type]
    assert hash[:valid]
    assert_kind_of Hash, hash[:checks]
  end

  def test_summary_returns_string
    result = EasyCodeSign::Verification::Result.new
    result.valid = true

    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test Signer")
    result.signer_certificate = cert
    result.signer_name = "Test Signer"

    summary = result.summary

    assert_includes summary, "VALID"
    assert_includes summary, "Test Signer"
  end
end

class TrustStoreTest < Minitest::Test
  def test_initializes_with_system_certs_by_default
    store = EasyCodeSign::Verification::TrustStore.new

    assert_instance_of OpenSSL::X509::Store, store.store
  end

  def test_initializes_without_system_certs
    store = EasyCodeSign::Verification::TrustStore.new(use_system_certs: false)

    assert_instance_of OpenSSL::X509::Store, store.store
  end

  def test_add_certificate
    store = EasyCodeSign::Verification::TrustStore.new(use_system_certs: false)

    # Create a self-signed certificate
    key = OpenSSL::PKey::RSA.new(2048)
    cert = create_self_signed_cert(key)

    result = store.add_certificate(cert)

    assert_same store, result # Returns self for chaining
  end

  def test_add_file_from_pem
    store = EasyCodeSign::Verification::TrustStore.new(use_system_certs: false)

    key = OpenSSL::PKey::RSA.new(2048)
    cert = create_self_signed_cert(key)

    temp_file = Tempfile.new(["cert", ".pem"])
    temp_file.write(cert.to_pem)
    temp_file.close

    result = store.add_file(temp_file.path)

    assert_same store, result
  ensure
    temp_file&.unlink
  end

  def test_verify_returns_hash
    store = EasyCodeSign::Verification::TrustStore.new(use_system_certs: false)

    key = OpenSSL::PKey::RSA.new(2048)
    cert = create_self_signed_cert(key)
    store.add_certificate(cert)

    result = store.verify(cert)

    assert_kind_of Hash, result
    assert_includes result.keys, :trusted
    assert_includes result.keys, :error
  end

  private

  def create_self_signed_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test CA")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 86_400 * 365
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end

class CertificateChainTest < Minitest::Test
  def setup
    @trust_store = EasyCodeSign::Verification::TrustStore.new(use_system_certs: false)
    @key = OpenSSL::PKey::RSA.new(2048)
    @cert = create_valid_cert(@key)
    @trust_store.add_certificate(@cert)
  end

  def test_validate_returns_result_object
    validator = EasyCodeSign::Verification::CertificateChain.new(@trust_store)

    result = validator.validate(@cert)

    assert_instance_of EasyCodeSign::Verification::ChainValidationResult, result
  end

  def test_validates_self_signed_trusted_cert
    validator = EasyCodeSign::Verification::CertificateChain.new(@trust_store)

    result = validator.validate(@cert)

    assert result.certificate_valid
  end

  def test_detects_expired_certificate
    validator = EasyCodeSign::Verification::CertificateChain.new(@trust_store)

    expired_key = OpenSSL::PKey::RSA.new(2048)
    expired_cert = create_expired_cert(expired_key)

    result = validator.validate(expired_cert)

    refute result.certificate_valid
    assert result.expired
    assert_any_match(result.errors, /expired/i)
  end

  private

  def create_valid_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test Cert")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 86_400
    cert.not_after = Time.now + 86_400 * 365
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def create_expired_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.parse("/CN=Expired Cert")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 86_400 * 365
    cert.not_after = Time.now - 86_400 # Expired yesterday
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def assert_any_match(array, pattern)
    assert array.any? { |item| item.match?(pattern) },
           "Expected at least one item in #{array.inspect} to match #{pattern.inspect}"
  end
end

class SignatureCheckerTest < Minitest::Test
  def test_verify_raw_with_valid_signature
    checker = EasyCodeSign::Verification::SignatureChecker.new

    key = OpenSSL::PKey::RSA.new(2048)
    cert = create_cert(key)
    content = "test content to sign"
    signature = key.sign(OpenSSL::Digest.new("SHA256"), content)

    result = checker.verify_raw(signature, content, cert, algorithm: :sha256)

    assert result.valid?
    assert result.signature_valid
  end

  def test_verify_raw_with_invalid_signature
    checker = EasyCodeSign::Verification::SignatureChecker.new

    key = OpenSSL::PKey::RSA.new(2048)
    cert = create_cert(key)
    content = "test content to sign"
    signature = "invalid signature data"

    result = checker.verify_raw(signature, content, cert, algorithm: :sha256)

    refute result.valid?
    refute result.signature_valid
  end

  def test_verify_raw_with_tampered_content
    checker = EasyCodeSign::Verification::SignatureChecker.new

    key = OpenSSL::PKey::RSA.new(2048)
    cert = create_cert(key)
    content = "original content"
    signature = key.sign(OpenSSL::Digest.new("SHA256"), content)

    result = checker.verify_raw(signature, "tampered content", cert, algorithm: :sha256)

    refute result.valid?
  end

  private

  def create_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 86_400
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end

class VerifierTest < EasyCodeSignTest
  def test_initializes_with_default_trust_store
    verifier = EasyCodeSign::Verifier.new

    assert_instance_of EasyCodeSign::Verification::TrustStore, verifier.trust_store
  end

  def test_initializes_with_custom_trust_store
    custom_store = EasyCodeSign::Verification::TrustStore.new(use_system_certs: false)
    verifier = EasyCodeSign::Verifier.new(trust_store: custom_store)

    assert_same custom_store, verifier.trust_store
  end

  def test_verify_unsigned_zip_returns_error
    temp_zip = Tempfile.new(["unsigned", ".zip"])
    Zip::File.open(temp_zip.path, Zip::File::CREATE) do |zip|
      zip.get_output_stream("test.txt") { |f| f.write("test") }
    end

    verifier = EasyCodeSign::Verifier.new
    result = verifier.verify(temp_zip.path)

    refute result.valid?
    assert_any_match(result.errors, /not signed/i)
  ensure
    temp_zip&.close
    temp_zip&.unlink
  end

  def test_verify_unsigned_gem_returns_error
    temp_gem = Tempfile.new(["unsigned", ".gem"])
    create_unsigned_gem(temp_gem.path)

    verifier = EasyCodeSign::Verifier.new
    result = verifier.verify(temp_gem.path)

    refute result.valid?
    assert_any_match(result.errors, /not signed/i)
  ensure
    temp_gem&.close
    temp_gem&.unlink
  end

  private

  def create_unsigned_gem(path)
    File.open(path, "wb") do |io|
      Gem::Package::TarWriter.new(io) do |tar|
        tar.add_file_simple("data.tar.gz", 0o644, 4) { |f| f.write("data") }
        tar.add_file_simple("metadata.gz", 0o644, 4) { |f| f.write("meta") }
        tar.add_file_simple("checksums.yaml.gz", 0o644, 4) { |f| f.write("sums") }
      end
    end
  end

  def assert_any_match(array, pattern)
    assert array.any? { |item| item.match?(pattern) },
           "Expected at least one item in #{array.inspect} to match #{pattern.inspect}"
  end
end
