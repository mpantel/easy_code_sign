# frozen_string_literal: true

# Native Messaging Protocol definitions
module EasySign
  module Protocol
    # Message types
    module Types
      SIGN = "sign"
      VERIFY = "verify"
      CHECK_AVAILABILITY = "check_availability"

      SIGN_RESPONSE = "sign_response"
      VERIFY_RESPONSE = "verify_response"
      AVAILABILITY_RESPONSE = "availability_response"
      ERROR = "error"
    end

    # Error codes
    module ErrorCodes
      TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND"
      PIN_INCORRECT = "PIN_INCORRECT"
      TOKEN_LOCKED = "TOKEN_LOCKED"
      INVALID_PDF = "INVALID_PDF"
      SIGNING_FAILED = "SIGNING_FAILED"
      VERIFICATION_FAILED = "VERIFICATION_FAILED"
      INVALID_MESSAGE = "INVALID_MESSAGE"
      INTERNAL_ERROR = "INTERNAL_ERROR"
    end

    class << self
      # Create a success response
      def success_response(request_id, type, payload)
        {
          type: type,
          requestId: request_id,
          payload: payload,
          error: nil
        }
      end

      # Create an error response
      def error_response(request_id, code, message, details = nil)
        {
          type: Types::ERROR,
          requestId: request_id,
          payload: nil,
          error: {
            code: code,
            message: message,
            details: details
          }.compact
        }
      end

      # Create sign response
      def sign_response(request_id, result)
        success_response(request_id, Types::SIGN_RESPONSE, {
          signedPdfData: result[:signed_pdf_data],
          signerName: result[:signer_name],
          signedAt: result[:signed_at]&.iso8601,
          timestamped: result[:timestamped] || false
        })
      end

      # Create verify response
      def verify_response(request_id, result)
        success_response(request_id, Types::VERIFY_RESPONSE, {
          valid: result[:valid],
          signerName: result[:signer_name],
          signerOrganization: result[:signer_organization],
          signedAt: result[:signed_at]&.iso8601,
          signatureValid: result[:signature_valid],
          integrityValid: result[:integrity_valid],
          certificateValid: result[:certificate_valid],
          chainValid: result[:chain_valid],
          trusted: result[:trusted],
          timestamped: result[:timestamped],
          timestampValid: result[:timestamp_valid],
          errors: result[:errors] || [],
          warnings: result[:warnings] || []
        })
      end

      # Create availability response
      def availability_response(request_id, result)
        success_response(request_id, Types::AVAILABILITY_RESPONSE, {
          available: result[:available],
          tokenPresent: result[:token_present],
          slots: result[:slots]&.map do |slot|
            {
              index: slot[:index],
              tokenLabel: slot[:token_label],
              manufacturer: slot[:manufacturer],
              serial: slot[:serial]
            }
          end
        })
      end
    end
  end
end
