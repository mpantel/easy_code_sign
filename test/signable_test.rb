# frozen_string_literal: true

require "test_helper"
require "tempfile"
require "zip"

class SignableBaseTest < Minitest::Test
  def test_raises_for_nonexistent_file
    assert_raises(EasyCodeSign::InvalidFileError) do
      EasyCodeSign::Signable::Base.new("/nonexistent/file.txt")
    end
  end

  def test_default_hash_algorithm_is_sha256
    file = Tempfile.new(["test", ".txt"])
    file.write("test content")
    file.close

    signable = TestSignable.new(file.path)
    assert_equal :sha256, signable.hash_algorithm
  ensure
    file.unlink
  end

  def test_compute_hash_returns_correct_digest
    file = Tempfile.new(["test", ".txt"])
    file.write("test content")
    file.close

    signable = TestSignable.new(file.path)
    expected = OpenSSL::Digest::SHA256.digest("hello")
    assert_equal expected, signable.compute_hash("hello")
  ensure
    file.unlink
  end

  def test_signature_algorithm_for_rsa
    file = Tempfile.new(["test", ".txt"])
    file.close

    signable = TestSignable.new(file.path)
    assert_equal :sha256_rsa, signable.signature_algorithm(:rsa)
  ensure
    file.unlink
  end

  # Concrete implementation for testing abstract base
  class TestSignable < EasyCodeSign::Signable::Base
    def prepare_for_signing; end
    def content_to_sign; "test"; end
    def apply_signature(sig, chain, timestamp_token: nil); file_path; end
    def extract_signature; nil; end
  end
end

class ZipFileSignableTest < Minitest::Test
  def setup
    @temp_zip = Tempfile.new(["test", ".zip"])
    create_test_zip(@temp_zip.path)
  end

  def teardown
    @temp_zip.close
    @temp_zip.unlink
  end

  def test_validates_zip_extension
    txt_file = Tempfile.new(["test", ".txt"])
    txt_file.write("content")
    txt_file.close

    assert_raises(EasyCodeSign::InvalidFileError) do
      EasyCodeSign::Signable::ZipFile.new(txt_file.path)
    end
  ensure
    txt_file.unlink
  end

  def test_accepts_valid_zip_file
    signable = EasyCodeSign::Signable::ZipFile.new(@temp_zip.path)
    assert_instance_of EasyCodeSign::Signable::ZipFile, signable
  end

  def test_file_list_returns_zip_contents
    signable = EasyCodeSign::Signable::ZipFile.new(@temp_zip.path)
    files = signable.file_list

    assert_includes files, "hello.txt"
    assert_includes files, "subdir/world.txt"
  end

  def test_prepare_for_signing_builds_manifest
    signable = EasyCodeSign::Signable::ZipFile.new(@temp_zip.path)
    signable.prepare_for_signing

    # Should not raise and content_to_sign should return data
    refute_nil signable.content_to_sign
  end

  def test_signed_returns_false_for_unsigned_zip
    signable = EasyCodeSign::Signable::ZipFile.new(@temp_zip.path)
    refute signable.signed?
  end

  def test_extract_signature_returns_nil_for_unsigned
    signable = EasyCodeSign::Signable::ZipFile.new(@temp_zip.path)
    assert_nil signable.extract_signature
  end

  private

  def create_test_zip(path)
    Zip::File.open(path, Zip::File::CREATE) do |zip|
      zip.get_output_stream("hello.txt") { |f| f.write("Hello, World!") }
      zip.get_output_stream("subdir/world.txt") { |f| f.write("Nested file") }
    end
  end
end

class GemFileSignableTest < Minitest::Test
  def setup
    @temp_gem = Tempfile.new(["test", ".gem"])
    create_test_gem(@temp_gem.path)
  end

  def teardown
    @temp_gem.close
    @temp_gem.unlink
  end

  def test_validates_gem_extension
    txt_file = Tempfile.new(["test", ".txt"])
    txt_file.write("content")
    txt_file.close

    assert_raises(EasyCodeSign::InvalidFileError) do
      EasyCodeSign::Signable::GemFile.new(txt_file.path)
    end
  ensure
    txt_file.unlink
  end

  def test_accepts_valid_gem_file
    signable = EasyCodeSign::Signable::GemFile.new(@temp_gem.path)
    assert_instance_of EasyCodeSign::Signable::GemFile, signable
  end

  def test_signed_returns_false_for_unsigned_gem
    signable = EasyCodeSign::Signable::GemFile.new(@temp_gem.path)
    refute signable.signed?
  end

  def test_prepare_for_signing_extracts_content
    signable = EasyCodeSign::Signable::GemFile.new(@temp_gem.path)
    signable.prepare_for_signing

    refute_nil signable.content_to_sign
  end

  private

  def create_test_gem(path)
    # Create a minimal gem-like tar archive
    File.open(path, "wb") do |io|
      Gem::Package::TarWriter.new(io) do |tar|
        # Add a fake data.tar.gz
        data = "fake gem data content"
        tar.add_file_simple("data.tar.gz", 0o644, data.bytesize) { |f| f.write(data) }

        # Add a fake metadata.gz
        metadata = "fake metadata content"
        tar.add_file_simple("metadata.gz", 0o644, metadata.bytesize) { |f| f.write(metadata) }

        # Add checksums
        checksums = "checksums content"
        tar.add_file_simple("checksums.yaml.gz", 0o644, checksums.bytesize) { |f| f.write(checksums) }
      end
    end
  end
end

class SignerTest < Minitest::Test
  def test_creates_signable_for_gem_extension
    signer = EasyCodeSign::Signer.new

    temp_gem = Tempfile.new(["test", ".gem"])
    create_minimal_gem(temp_gem.path)

    signable = signer.send(:create_signable, temp_gem.path)
    assert_instance_of EasyCodeSign::Signable::GemFile, signable
  ensure
    temp_gem&.close
    temp_gem&.unlink
  end

  def test_creates_signable_for_zip_extension
    signer = EasyCodeSign::Signer.new

    temp_zip = Tempfile.new(["test", ".zip"])
    Zip::File.open(temp_zip.path, Zip::File::CREATE) do |zip|
      zip.get_output_stream("test.txt") { |f| f.write("test") }
    end

    signable = signer.send(:create_signable, temp_zip.path)
    assert_instance_of EasyCodeSign::Signable::ZipFile, signable
  ensure
    temp_zip&.close
    temp_zip&.unlink
  end

  def test_raises_for_unsupported_extension
    signer = EasyCodeSign::Signer.new

    temp_file = Tempfile.new(["test", ".exe"])
    temp_file.close

    assert_raises(EasyCodeSign::InvalidFileError) do
      signer.send(:create_signable, temp_file.path)
    end
  ensure
    temp_file&.unlink
  end

  private

  def create_minimal_gem(path)
    File.open(path, "wb") do |io|
      Gem::Package::TarWriter.new(io) do |tar|
        tar.add_file_simple("data.tar.gz", 0o644, 4) { |f| f.write("data") }
        tar.add_file_simple("metadata.gz", 0o644, 4) { |f| f.write("meta") }
        tar.add_file_simple("checksums.yaml.gz", 0o644, 4) { |f| f.write("sums") }
      end
    end
  end
end

class SigningResultTest < Minitest::Test
  def test_timestamped_returns_true_when_timestamp_present
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test Signer")

    token = EasyCodeSign::Timestamp::TimestampToken.new(
      token_der: "fake",
      timestamp: Time.now,
      serial_number: 1,
      policy_oid: "1.2.3",
      tsa_url: "http://tsa.example.com"
    )

    result = EasyCodeSign::SigningResult.new(
      file_path: "/path/to/file",
      certificate: cert,
      algorithm: :sha256_rsa,
      timestamp_token: token,
      signed_at: Time.now
    )

    assert result.timestamped?
  end

  def test_timestamped_returns_false_when_no_timestamp
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test Signer")

    result = EasyCodeSign::SigningResult.new(
      file_path: "/path/to/file",
      certificate: cert,
      algorithm: :sha256_rsa,
      timestamp_token: nil,
      signed_at: Time.now
    )

    refute result.timestamped?
  end

  def test_signer_name_returns_certificate_subject
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test Signer/O=Test Org")

    result = EasyCodeSign::SigningResult.new(
      file_path: "/path/to/file",
      certificate: cert,
      algorithm: :sha256_rsa,
      timestamp_token: nil,
      signed_at: Time.now
    )

    assert_includes result.signer_name, "Test Signer"
  end

  def test_to_h_returns_hash_representation
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test")
    signed_at = Time.now

    result = EasyCodeSign::SigningResult.new(
      file_path: "/path/to/file.gem",
      certificate: cert,
      algorithm: :sha256_rsa,
      timestamp_token: nil,
      signed_at: signed_at
    )

    hash = result.to_h
    assert_equal "/path/to/file.gem", hash[:file_path]
    assert_equal :sha256_rsa, hash[:algorithm]
    assert_equal false, hash[:timestamped]
    assert_equal signed_at, hash[:signed_at]
  end

  def test_timestamp_returns_time_from_token
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test")
    ts_time = Time.utc(2024, 1, 15, 12, 0, 0)

    token = EasyCodeSign::Timestamp::TimestampToken.new(
      token_der: "fake",
      timestamp: ts_time,
      serial_number: 1,
      policy_oid: "1.2.3",
      tsa_url: "http://tsa.example.com"
    )

    result = EasyCodeSign::SigningResult.new(
      file_path: "/path/to/file",
      certificate: cert,
      algorithm: :sha256_rsa,
      timestamp_token: token,
      signed_at: Time.now
    )

    assert_equal ts_time, result.timestamp
  end
end
