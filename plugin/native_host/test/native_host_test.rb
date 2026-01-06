# frozen_string_literal: true

require "minitest/autorun"
require "json"

# Add paths for testing
$LOAD_PATH.unshift(File.expand_path("../../src", __dir__))
$LOAD_PATH.unshift(File.expand_path("../../../lib", __dir__))

require "protocol"

class ProtocolTest < Minitest::Test
  def test_sign_response_creates_correct_structure
    result = {
      signed_pdf_data: "base64data",
      signer_name: "CN=Test User",
      signed_at: Time.now,
      timestamped: true
    }

    response = EasySign::Protocol.sign_response("req-123", result)

    assert_equal "sign_response", response[:type]
    assert_equal "req-123", response[:requestId]
    assert_nil response[:error]
    assert_equal "base64data", response[:payload][:signedPdfData]
    assert_equal "CN=Test User", response[:payload][:signerName]
    assert response[:payload][:timestamped]
  end

  def test_error_response_creates_correct_structure
    response = EasySign::Protocol.error_response(
      "req-456",
      EasySign::Protocol::ErrorCodes::PIN_INCORRECT,
      "Wrong PIN",
      { retriesRemaining: 2 }
    )

    assert_equal "error", response[:type]
    assert_equal "req-456", response[:requestId]
    assert_nil response[:payload]
    assert_equal "PIN_INCORRECT", response[:error][:code]
    assert_equal "Wrong PIN", response[:error][:message]
    assert_equal 2, response[:error][:details][:retriesRemaining]
  end

  def test_verify_response_creates_correct_structure
    result = {
      valid: true,
      signer_name: "CN=Test User",
      signature_valid: true,
      integrity_valid: true,
      certificate_valid: true,
      chain_valid: true,
      trusted: true,
      timestamped: false,
      errors: [],
      warnings: []
    }

    response = EasySign::Protocol.verify_response("req-789", result)

    assert_equal "verify_response", response[:type]
    assert_equal "req-789", response[:requestId]
    assert response[:payload][:valid]
    assert response[:payload][:signatureValid]
    assert_empty response[:payload][:errors]
  end

  def test_availability_response_creates_correct_structure
    result = {
      available: true,
      token_present: true,
      slots: [
        { index: 0, token_label: "Token1", manufacturer: "SafeNet", serial: "12345" }
      ]
    }

    response = EasySign::Protocol.availability_response("req-000", result)

    assert_equal "availability_response", response[:type]
    assert response[:payload][:available]
    assert response[:payload][:tokenPresent]
    assert_equal 1, response[:payload][:slots].length
    assert_equal "Token1", response[:payload][:slots][0][:tokenLabel]
  end
end

class MessageFormatTest < Minitest::Test
  def test_native_message_encoding
    message = { type: "test", requestId: "123" }
    json = message.to_json
    length = [json.bytesize].pack("V")

    # Verify length prefix format
    assert_equal 4, length.bytesize
    assert_equal json.bytesize, length.unpack1("V")
  end

  def test_native_message_decoding
    message = { type: "sign", requestId: "abc", payload: { pdfData: "test" } }
    json = message.to_json
    length_bytes = [json.bytesize].pack("V")

    # Simulate reading
    decoded_length = length_bytes.unpack1("V")
    assert_equal json.bytesize, decoded_length

    decoded = JSON.parse(json, symbolize_names: true)
    assert_equal "sign", decoded[:type]
    assert_equal "abc", decoded[:requestId]
  end
end
