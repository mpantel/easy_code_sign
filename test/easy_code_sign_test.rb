# frozen_string_literal: true

require "test_helper"

class EasyCodeSignModuleTest < EasyCodeSignTest
  def test_has_version_number
    refute_nil EasyCodeSign::VERSION
  end

  def test_configure_yields_configuration_object
    yielded = nil
    EasyCodeSign.configure { |c| yielded = c }
    assert_instance_of EasyCodeSign::Configuration, yielded
  end

  def test_configure_allows_setting_values
    EasyCodeSign.configure do |config|
      config.provider = :safenet
      config.timestamp_authority = "http://timestamp.example.com"
    end

    assert_equal :safenet, EasyCodeSign.configuration.provider
    assert_equal "http://timestamp.example.com", EasyCodeSign.configuration.timestamp_authority
  end

  def test_configuration_returns_configuration_instance
    assert_instance_of EasyCodeSign::Configuration, EasyCodeSign.configuration
  end

  def test_configuration_returns_same_instance
    assert_same EasyCodeSign.configuration, EasyCodeSign.configuration
  end

  def test_reset_configuration_creates_new_instance
    old_config = EasyCodeSign.configuration
    EasyCodeSign.reset_configuration!
    refute_same old_config, EasyCodeSign.configuration
  end
end

class ConfigurationTest < EasyCodeSignTest
  def setup
    super
    @config = EasyCodeSign::Configuration.new
  end

  def test_default_provider_is_safenet
    assert_equal :safenet, @config.provider
  end

  def test_default_timestamp_hash_algorithm_is_sha256
    assert_equal :sha256, @config.timestamp_hash_algorithm
  end

  def test_default_require_timestamp_is_false
    refute @config.require_timestamp
  end

  def test_default_check_revocation_is_true
    assert @config.check_revocation
  end

  def test_default_network_timeout_is_30
    assert_equal 30, @config.network_timeout
  end

  def test_default_slot_index_is_0
    assert_equal 0, @config.slot_index
  end

  def test_validate_raises_when_provider_nil
    @config.provider = nil
    error = assert_raises(EasyCodeSign::ConfigurationError) { @config.validate! }
    assert_match(/Provider/, error.message)
  end

  def test_validate_raises_when_pkcs11_library_nil
    @config.provider = :safenet
    @config.pkcs11_library = nil
    error = assert_raises(EasyCodeSign::ConfigurationError) { @config.validate! }
    assert_match(/PKCS#11 library/, error.message)
  end

  def test_validate_raises_when_require_timestamp_without_tsa
    @config.pkcs11_library = __FILE__
    @config.require_timestamp = true
    @config.timestamp_authority = nil
    error = assert_raises(EasyCodeSign::ConfigurationError) { @config.validate! }
    assert_match(/Timestamp authority/, error.message)
  end
end

class ErrorsTest < Minitest::Test
  def test_error_is_standard_error
    assert_kind_of StandardError, EasyCodeSign::Error.new
  end

  def test_pin_error_stores_retries_remaining
    error = EasyCodeSign::PinError.new("Wrong PIN", retries_remaining: 2)
    assert_equal 2, error.retries_remaining
  end

  def test_pkcs11_error_stores_error_code
    error = EasyCodeSign::Pkcs11Error.new("PKCS11 failure", pkcs11_error_code: 0x00000003)
    assert_equal 0x00000003, error.pkcs11_error_code
  end

  def test_certificate_chain_error_stores_certificate_and_reason
    error = EasyCodeSign::CertificateChainError.new(
      "Invalid chain",
      certificate: "cert_data",
      reason: :expired
    )
    assert_equal "cert_data", error.certificate
    assert_equal :expired, error.reason
  end

  def test_timestamp_authority_error_stores_http_status
    error = EasyCodeSign::TimestampAuthorityError.new("TSA failed", http_status: 503)
    assert_equal 503, error.http_status
  end
end
