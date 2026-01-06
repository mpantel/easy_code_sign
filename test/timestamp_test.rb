# frozen_string_literal: true

require "test_helper"

class TimestampRequestTest < Minitest::Test
  def test_creates_request_with_defaults
    request = EasyCodeSign::Timestamp::Request.new("test data")

    assert_equal :sha256, request.algorithm
    assert request.cert_req
    assert_nil request.policy_oid
    refute_nil request.nonce
  end

  def test_computes_message_imprint_hash
    data = "test signature data"
    request = EasyCodeSign::Timestamp::Request.new(data, algorithm: :sha256)

    expected = OpenSSL::Digest::SHA256.digest(data)
    assert_equal expected, request.message_imprint_hash
  end

  def test_supports_different_algorithms
    data = "test data"

    sha256_request = EasyCodeSign::Timestamp::Request.new(data, algorithm: :sha256)
    sha384_request = EasyCodeSign::Timestamp::Request.new(data, algorithm: :sha384)
    sha512_request = EasyCodeSign::Timestamp::Request.new(data, algorithm: :sha512)

    assert_equal "2.16.840.1.101.3.4.2.1", sha256_request.algorithm_oid
    assert_equal "2.16.840.1.101.3.4.2.2", sha384_request.algorithm_oid
    assert_equal "2.16.840.1.101.3.4.2.3", sha512_request.algorithm_oid
  end

  def test_to_der_produces_valid_asn1
    request = EasyCodeSign::Timestamp::Request.new("test data")
    der = request.to_der

    # Should be parseable ASN.1
    asn1 = OpenSSL::ASN1.decode(der)
    assert_instance_of OpenSSL::ASN1::Sequence, asn1

    # First element should be version (INTEGER 1)
    assert_equal 1, asn1.value[0].value
  end

  def test_generates_unique_nonces
    request1 = EasyCodeSign::Timestamp::Request.new("data")
    request2 = EasyCodeSign::Timestamp::Request.new("data")

    refute_equal request1.nonce, request2.nonce
  end

  def test_raises_for_unsupported_algorithm
    assert_raises(ArgumentError) do
      EasyCodeSign::Timestamp::Request.new("data", algorithm: :md5).algorithm_oid
    end
  end
end

class TimestampClientTest < Minitest::Test
  def test_initializes_with_url
    client = EasyCodeSign::Timestamp::Client.new("http://timestamp.example.com")

    assert_equal "http://timestamp.example.com", client.url
    assert_equal 30, client.timeout
    assert_nil client.username
    assert_nil client.password
  end

  def test_initializes_with_custom_options
    client = EasyCodeSign::Timestamp::Client.new(
      "http://timestamp.example.com",
      timeout: 60,
      username: "user",
      password: "pass"
    )

    assert_equal 60, client.timeout
    assert_equal "user", client.username
    assert_equal "pass", client.password
  end

  def test_known_tsas_are_defined
    assert_includes EasyCodeSign::Timestamp::Client::KNOWN_TSAS, :digicert
    assert_includes EasyCodeSign::Timestamp::Client::KNOWN_TSAS, :globalsign
    assert_includes EasyCodeSign::Timestamp::Client::KNOWN_TSAS, :sectigo
  end
end

class TimestampTokenTest < Minitest::Test
  def setup
    @token = EasyCodeSign::Timestamp::TimestampToken.new(
      token_der: "fake_der_data",
      timestamp: Time.utc(2024, 1, 15, 12, 0, 0),
      serial_number: 12345,
      policy_oid: "1.2.3.4",
      tsa_url: "http://timestamp.example.com"
    )
  end

  def test_stores_all_attributes
    assert_equal "fake_der_data", @token.token_der
    assert_equal 12345, @token.serial_number
    assert_equal "1.2.3.4", @token.policy_oid
    assert_equal "http://timestamp.example.com", @token.tsa_url
  end

  def test_timestamp_iso8601
    assert_equal "2024-01-15T12:00:00Z", @token.timestamp_iso8601
  end

  def test_to_h_returns_hash
    hash = @token.to_h

    assert_equal "2024-01-15T12:00:00Z", hash[:timestamp]
    assert_equal 12345, hash[:serial_number]
    assert_equal "1.2.3.4", hash[:policy_oid]
    assert_equal "http://timestamp.example.com", hash[:tsa_url]
  end
end

class TimestampVerifierTest < Minitest::Test
  def test_initializes_with_default_trust_store
    verifier = EasyCodeSign::Timestamp::Verifier.new

    assert_instance_of OpenSSL::X509::Store, verifier.trust_store
  end

  def test_initializes_with_custom_trust_store
    custom_store = OpenSSL::X509::Store.new
    verifier = EasyCodeSign::Timestamp::Verifier.new(trust_store: custom_store)

    assert_same custom_store, verifier.trust_store
  end
end

class TimestampVerificationResultTest < Minitest::Test
  def test_initializes_with_default_values
    result = EasyCodeSign::Timestamp::VerificationResult.new

    refute result.valid?
    refute result.token_parsed
    refute result.signature_valid
    refute result.imprint_valid
    refute result.chain_valid
    assert_empty result.errors
    assert_empty result.warnings
  end

  def test_to_h_returns_complete_hash
    result = EasyCodeSign::Timestamp::VerificationResult.new
    result.valid = true
    result.timestamp = Time.utc(2024, 1, 15)
    result.serial_number = 123

    hash = result.to_h

    assert hash[:valid]
    assert_equal Time.utc(2024, 1, 15), hash[:timestamp]
    assert_equal 123, hash[:serial_number]
  end
end
