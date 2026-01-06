# frozen_string_literal: true

require "openssl"

module EasyCodeSign
  module Timestamp
    # RFC 3161 Timestamp Response parser
    #
    # Parses TimeStampResp ASN.1 structures returned by TSAs.
    #
    # @example
    #   response = Timestamp::Response.parse(der_bytes)
    #   if response.success?
    #     puts response.timestamp
    #     puts response.serial_number
    #   end
    #
    class Response
      # PKIStatus values
      STATUS_GRANTED = 0
      STATUS_GRANTED_WITH_MODS = 1
      STATUS_REJECTION = 2
      STATUS_WAITING = 3
      STATUS_REVOCATION_WARNING = 4
      STATUS_REVOCATION_NOTIFICATION = 5

      STATUS_NAMES = {
        STATUS_GRANTED => "granted",
        STATUS_GRANTED_WITH_MODS => "granted_with_mods",
        STATUS_REJECTION => "rejection",
        STATUS_WAITING => "waiting",
        STATUS_REVOCATION_WARNING => "revocation_warning",
        STATUS_REVOCATION_NOTIFICATION => "revocation_notification"
      }.freeze

      attr_reader :raw_response, :status, :status_string, :failure_info,
                  :timestamp_token, :tst_info

      # Parse a DER-encoded TimeStampResp
      # @param der [String] DER-encoded response
      # @return [Response]
      def self.parse(der)
        new(der)
      end

      def initialize(der)
        @raw_response = der
        parse_response
      end

      # Check if the timestamp was granted
      # @return [Boolean]
      def success?
        status == STATUS_GRANTED || status == STATUS_GRANTED_WITH_MODS
      end

      # Check if there was a failure
      # @return [Boolean]
      def failure?
        !success?
      end

      # Get the timestamp time
      # @return [Time, nil]
      def timestamp
        return nil unless @tst_info

        @timestamp ||= extract_gen_time
      end

      # Get the TSA serial number
      # @return [Integer, nil]
      def serial_number
        return nil unless @tst_info

        @serial_number ||= extract_serial_number
      end

      # Get the nonce from the response
      # @return [Integer, nil]
      def nonce
        return nil unless @tst_info

        @nonce ||= extract_nonce
      end

      # Get the message imprint hash from the response
      # @return [String, nil]
      def message_imprint_hash
        return nil unless @tst_info

        @message_imprint_hash ||= extract_message_imprint
      end

      # Get the TSA policy OID
      # @return [String, nil]
      def policy_oid
        return nil unless @tst_info

        @policy_oid ||= extract_policy
      end

      # Get the raw timestamp token (CMS SignedData)
      # @return [String, nil] DER-encoded token
      def token_der
        return nil unless @timestamp_token

        @timestamp_token.to_der
      end

      # Verify the nonce matches the request
      # @param request_nonce [Integer]
      # @return [Boolean]
      def nonce_matches?(request_nonce)
        nonce == request_nonce
      end

      # Get human-readable status
      # @return [String]
      def status_name
        STATUS_NAMES[status] || "unknown(#{status})"
      end

      # Get error message if failed
      # @return [String, nil]
      def error_message
        return nil if success?

        msg = "Timestamp request failed: #{status_name}"
        msg += " - #{status_string}" if status_string
        msg += " (failure: #{failure_info})" if failure_info
        msg
      end

      private

      def parse_response
        # TimeStampResp ::= SEQUENCE {
        #   status          PKIStatusInfo,
        #   timeStampToken  TimeStampToken OPTIONAL
        # }

        asn1 = OpenSSL::ASN1.decode(raw_response)
        raise InvalidTimestampError, "Invalid response structure" unless asn1.is_a?(OpenSSL::ASN1::Sequence)

        parse_status_info(asn1.value[0])

        if asn1.value[1] && success?
          parse_timestamp_token(asn1.value[1])
        end
      rescue OpenSSL::ASN1::ASN1Error => e
        raise InvalidTimestampError, "Failed to parse timestamp response: #{e.message}"
      end

      def parse_status_info(status_info)
        # PKIStatusInfo ::= SEQUENCE {
        #   status        PKIStatus,
        #   statusString  PKIFreeText OPTIONAL,
        #   failInfo      PKIFailureInfo OPTIONAL
        # }

        @status = status_info.value[0].value.to_i

        if status_info.value[1]
          @status_string = extract_status_string(status_info.value[1])
        end

        if status_info.value[2]
          @failure_info = status_info.value[2].value
        end
      end

      def extract_status_string(asn1)
        # PKIFreeText is a SEQUENCE of UTF8String
        return asn1.value if asn1.is_a?(OpenSSL::ASN1::UTF8String)
        return asn1.value.map(&:value).join("; ") if asn1.is_a?(OpenSSL::ASN1::Sequence)

        asn1.value.to_s
      end

      def parse_timestamp_token(token_asn1)
        # TimeStampToken is ContentInfo containing SignedData
        @timestamp_token = OpenSSL::PKCS7.new(token_asn1.to_der)

        # Extract TSTInfo from the SignedData content
        signed_data_content = @timestamp_token.data
        @tst_info = OpenSSL::ASN1.decode(signed_data_content) if signed_data_content
      rescue OpenSSL::PKCS7::PKCS7Error => e
        raise InvalidTimestampError, "Invalid timestamp token: #{e.message}"
      end

      def extract_gen_time
        # TSTInfo.genTime is at a specific position in the sequence
        return nil unless @tst_info.is_a?(OpenSSL::ASN1::Sequence)

        # genTime is typically the 4th element (index 3) in TSTInfo
        @tst_info.value.each do |elem|
          if elem.is_a?(OpenSSL::ASN1::GeneralizedTime) || elem.is_a?(OpenSSL::ASN1::UTCTime)
            return elem.value
          end
        end
        nil
      end

      def extract_serial_number
        return nil unless @tst_info.is_a?(OpenSSL::ASN1::Sequence)

        # serialNumber is the 2nd element (index 1)
        serial = @tst_info.value[1]
        serial.is_a?(OpenSSL::ASN1::Integer) ? serial.value.to_i : nil
      end

      def extract_nonce
        return nil unless @tst_info.is_a?(OpenSSL::ASN1::Sequence)

        # nonce is optional, look for it after the mandatory fields
        @tst_info.value.each do |elem|
          next unless elem.is_a?(OpenSSL::ASN1::Integer)
          next if elem == @tst_info.value[1] # Skip serial number

          return elem.value.to_i
        end
        nil
      end

      def extract_message_imprint
        return nil unless @tst_info.is_a?(OpenSSL::ASN1::Sequence)

        # messageImprint is the 3rd element (index 2)
        imprint = @tst_info.value[2]
        return nil unless imprint.is_a?(OpenSSL::ASN1::Sequence)

        # Get the hash value (2nd element of MessageImprint)
        imprint.value[1]&.value
      end

      def extract_policy
        return nil unless @tst_info.is_a?(OpenSSL::ASN1::Sequence)

        # policy is the 1st element (index 0)
        policy = @tst_info.value[0]
        policy.is_a?(OpenSSL::ASN1::ObjectId) ? policy.oid : nil
      end
    end
  end
end
