#!/usr/bin/env ruby
# frozen_string_literal: true

# EasySign Native Messaging Host
# Communicates with browser extension via stdin/stdout using length-prefixed JSON

require "json"

# Add lib to load path for development
$LOAD_PATH.unshift(File.expand_path("../../../lib", __dir__))
$LOAD_PATH.unshift(__dir__)

require "protocol"
require "signing_service"

module EasySign
  # Native Messaging Host for browser extension communication
  class NativeHost
    MAX_MESSAGE_SIZE = 1024 * 1024 # 1MB limit

    def initialize
      @signing_service = SigningService.new

      # Ensure binary mode for stdin/stdout
      $stdin.binmode
      $stdout.binmode

      # Disable stdout buffering
      $stdout.sync = true
    end

    # Main loop - read and process messages
    def run
      loop do
        message = read_message
        break unless message

        response = process_message(message)
        write_message(response)
      end
    rescue Interrupt
      # Clean exit on Ctrl+C (shouldn't happen in normal use)
      exit 0
    rescue StandardError => e
      # Log error but don't crash - browser will handle disconnect
      write_message(Protocol.error_response(nil, Protocol::ErrorCodes::INTERNAL_ERROR, e.message))
    end

    private

    # Read a native messaging message from stdin
    # Format: 4-byte length (little-endian uint32) + JSON data
    def read_message
      # Read 4-byte length prefix
      length_bytes = $stdin.read(4)
      return nil unless length_bytes && length_bytes.bytesize == 4

      # Unpack as little-endian unsigned 32-bit integer
      length = length_bytes.unpack1("V")

      # Validate length
      return nil if length.zero? || length > MAX_MESSAGE_SIZE

      # Read JSON data
      json_data = $stdin.read(length)
      return nil unless json_data && json_data.bytesize == length

      JSON.parse(json_data, symbolize_names: true)
    rescue JSON::ParserError => e
      # Return error for invalid JSON
      { type: "invalid", error: e.message }
    end

    # Write a native messaging message to stdout
    # Format: 4-byte length (little-endian uint32) + JSON data
    def write_message(message)
      json = message.to_json
      length = [json.bytesize].pack("V") # Little-endian uint32

      $stdout.write(length)
      $stdout.write(json)
      $stdout.flush
    end

    # Process an incoming message and return response
    def process_message(message)
      request_id = message[:requestId] || message[:request_id]
      type = message[:type]

      case type
      when Protocol::Types::SIGN
        process_sign(request_id, message[:payload])
      when Protocol::Types::VERIFY
        process_verify(request_id, message[:payload])
      when Protocol::Types::CHECK_AVAILABILITY
        process_check_availability(request_id)
      when "invalid"
        Protocol.error_response(request_id, Protocol::ErrorCodes::INVALID_MESSAGE, message[:error])
      else
        Protocol.error_response(request_id, Protocol::ErrorCodes::INVALID_MESSAGE, "Unknown message type: #{type}")
      end
    end

    def process_sign(request_id, payload)
      result = @signing_service.sign(
        pdf_data: payload[:pdfData],
        pin: payload[:pin],
        options: payload[:options] || {}
      )

      Protocol.sign_response(request_id, result)
    rescue EasyCodeSign::PinError => e
      Protocol.error_response(
        request_id,
        Protocol::ErrorCodes::PIN_INCORRECT,
        e.message,
        { retriesRemaining: e.respond_to?(:retries_remaining) ? e.retries_remaining : nil }
      )
    rescue EasyCodeSign::TokenNotFoundError => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::TOKEN_NOT_FOUND, e.message)
    rescue EasyCodeSign::TokenLockedError => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::TOKEN_LOCKED, e.message)
    rescue EasyCodeSign::InvalidPdfError => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::INVALID_PDF, e.message)
    rescue EasyCodeSign::Error => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::SIGNING_FAILED, e.message)
    rescue StandardError => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::INTERNAL_ERROR, e.message)
    end

    def process_verify(request_id, payload)
      result = @signing_service.verify(
        pdf_data: payload[:pdfData],
        check_timestamp: payload[:checkTimestamp] != false
      )

      Protocol.verify_response(request_id, result)
    rescue EasyCodeSign::InvalidPdfError => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::INVALID_PDF, e.message)
    rescue EasyCodeSign::Error => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::VERIFICATION_FAILED, e.message)
    rescue StandardError => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::INTERNAL_ERROR, e.message)
    end

    def process_check_availability(request_id)
      result = @signing_service.check_availability
      Protocol.availability_response(request_id, result)
    rescue StandardError => e
      Protocol.error_response(request_id, Protocol::ErrorCodes::INTERNAL_ERROR, e.message)
    end
  end
end

# Entry point
if __FILE__ == $PROGRAM_NAME
  EasySign::NativeHost.new.run
end
