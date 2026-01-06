# frozen_string_literal: true

require "openssl"

module EasyCodeSign
  module Timestamp
    # Verifies RFC 3161 timestamp tokens
    #
    # @example
    #   verifier = Timestamp::Verifier.new
    #   result = verifier.verify(token_der, original_data)
    #
    class Verifier
      attr_reader :trust_store

      # Create a new timestamp verifier
      #
      # @param trust_store [OpenSSL::X509::Store, nil] custom trust store
      #
      def initialize(trust_store: nil)
        @trust_store = trust_store || build_default_trust_store
      end

      # Verify a timestamp token
      #
      # @param token_der [String] DER-encoded timestamp token
      # @param original_data [String] the data that was timestamped
      # @param algorithm [Symbol] hash algorithm used (:sha256, :sha384, :sha512)
      # @return [VerificationResult]
      #
      def verify(token_der, original_data, algorithm: :sha256)
        result = VerificationResult.new

        begin
          pkcs7 = OpenSSL::PKCS7.new(token_der)
          result.token_parsed = true

          # Verify PKCS#7 signature
          verify_pkcs7_signature(pkcs7, result)

          # Parse and verify TSTInfo
          tst_info = parse_tst_info(pkcs7)
          result.tst_info_parsed = true

          # Verify message imprint
          verify_message_imprint(tst_info, original_data, algorithm, result)

          # Extract timestamp info
          extract_timestamp_info(tst_info, result)

          # Verify certificate chain
          verify_certificate_chain(pkcs7, result)

          result.valid = result.signature_valid && result.imprint_valid && result.chain_valid
        rescue OpenSSL::PKCS7::PKCS7Error => e
          result.errors << "PKCS#7 error: #{e.message}"
        rescue OpenSSL::ASN1::ASN1Error => e
          result.errors << "ASN.1 parsing error: #{e.message}"
        rescue StandardError => e
          result.errors << "Verification error: #{e.message}"
        end

        result
      end

      private

      def build_default_trust_store
        store = OpenSSL::X509::Store.new
        store.set_default_paths
        store
      end

      def verify_pkcs7_signature(pkcs7, result)
        # Verify the PKCS#7 signature using embedded certificates
        if pkcs7.verify(pkcs7.certificates, trust_store, nil, OpenSSL::PKCS7::NOVERIFY)
          result.signature_valid = true
        else
          result.signature_valid = false
          result.errors << "PKCS#7 signature verification failed"
        end
      rescue OpenSSL::PKCS7::PKCS7Error => e
        result.signature_valid = false
        result.errors << "Signature verification error: #{e.message}"
      end

      def parse_tst_info(pkcs7)
        content = pkcs7.data
        raise InvalidTimestampError, "No content in timestamp token" unless content

        OpenSSL::ASN1.decode(content)
      end

      def verify_message_imprint(tst_info, original_data, algorithm, result)
        # Extract message imprint from TSTInfo
        return unless tst_info.is_a?(OpenSSL::ASN1::Sequence)

        imprint_seq = tst_info.value[2]
        return unless imprint_seq.is_a?(OpenSSL::ASN1::Sequence)

        # Get the hash from the timestamp
        ts_hash = imprint_seq.value[1]&.value

        # Compute expected hash
        expected_hash = digest_class(algorithm).digest(original_data)

        if ts_hash == expected_hash
          result.imprint_valid = true
        else
          result.imprint_valid = false
          result.errors << "Message imprint does not match original data"
        end
      end

      def extract_timestamp_info(tst_info, result)
        return unless tst_info.is_a?(OpenSSL::ASN1::Sequence)

        # Extract policy OID (index 0)
        if tst_info.value[0].is_a?(OpenSSL::ASN1::ObjectId)
          result.policy_oid = tst_info.value[0].oid
        end

        # Extract serial number (index 1)
        if tst_info.value[1].is_a?(OpenSSL::ASN1::Integer)
          result.serial_number = tst_info.value[1].value.to_i
        end

        # Extract genTime
        tst_info.value.each do |elem|
          if elem.is_a?(OpenSSL::ASN1::GeneralizedTime) || elem.is_a?(OpenSSL::ASN1::UTCTime)
            result.timestamp = elem.value
            break
          end
        end
      end

      def verify_certificate_chain(pkcs7, result)
        certs = pkcs7.certificates
        return unless certs&.any?

        result.tsa_certificate = certs.first

        # Verify the TSA certificate chain
        begin
          if trust_store.verify(certs.first, certs)
            result.chain_valid = true
          else
            result.chain_valid = false
            result.errors << "TSA certificate chain validation failed: #{trust_store.error_string}"
          end
        rescue OpenSSL::X509::StoreError => e
          result.chain_valid = false
          result.errors << "Certificate chain error: #{e.message}"
        end

        # Check if TSA certificate has extended key usage for timestamping
        verify_tsa_extended_key_usage(certs.first, result)
      end

      def verify_tsa_extended_key_usage(cert, result)
        return unless cert

        eku = cert.extensions.find { |e| e.oid == "extendedKeyUsage" }
        return unless eku

        unless eku.value.include?("Time Stamping")
          result.warnings << "TSA certificate does not have Time Stamping extended key usage"
        end
      end

      def digest_class(algorithm)
        case algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        else raise ArgumentError, "Unsupported algorithm: #{algorithm}"
        end
      end
    end

    # Result of timestamp verification
    class VerificationResult
      attr_accessor :valid, :token_parsed, :tst_info_parsed,
                    :signature_valid, :imprint_valid, :chain_valid,
                    :timestamp, :serial_number, :policy_oid,
                    :tsa_certificate, :errors, :warnings

      def initialize
        @valid = false
        @token_parsed = false
        @tst_info_parsed = false
        @signature_valid = false
        @imprint_valid = false
        @chain_valid = false
        @timestamp = nil
        @serial_number = nil
        @policy_oid = nil
        @tsa_certificate = nil
        @errors = []
        @warnings = []
      end

      def valid?
        valid
      end

      def tsa_name
        tsa_certificate&.subject&.to_s
      end

      def to_h
        {
          valid: valid,
          timestamp: timestamp,
          serial_number: serial_number,
          policy_oid: policy_oid,
          tsa_name: tsa_name,
          signature_valid: signature_valid,
          imprint_valid: imprint_valid,
          chain_valid: chain_valid,
          errors: errors,
          warnings: warnings
        }
      end
    end
  end
end
