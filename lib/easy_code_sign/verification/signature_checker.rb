# frozen_string_literal: true

require "openssl"

module EasyCodeSign
  module Verification
    # Performs cryptographic signature verification
    #
    # Handles PKCS#7 signature verification for both gem and ZIP files.
    #
    class SignatureChecker
      # Verify a PKCS#7 signature
      #
      # @param pkcs7_der [String] DER-encoded PKCS#7 signature
      # @param content [String] the signed content
      # @param trust_store [TrustStore] trust store for verification
      # @return [SignatureCheckResult]
      #
      def verify_pkcs7(pkcs7_der, content, trust_store)
        result = SignatureCheckResult.new

        begin
          pkcs7 = OpenSSL::PKCS7.new(pkcs7_der)
          result.signature_parsed = true

          # Extract certificates
          result.certificates = pkcs7.certificates || []
          result.signer_certificate = result.certificates.first

          # Verify the signature
          # NOVERIFY flag skips certificate chain verification (we do that separately)
          flags = OpenSSL::PKCS7::NOVERIFY

          if pkcs7.verify(result.certificates, trust_store.store, content, flags)
            result.signature_valid = true
          else
            result.signature_valid = false
            result.add_error("PKCS#7 signature verification failed")
          end

          # Extract signature algorithm info
          extract_signature_info(pkcs7, result)

        rescue OpenSSL::PKCS7::PKCS7Error => e
          result.signature_valid = false
          result.add_error("PKCS#7 error: #{e.message}")
        rescue StandardError => e
          result.signature_valid = false
          result.add_error("Signature verification error: #{e.message}")
        end

        result
      end

      # Verify a detached PKCS#7 signature (signature separate from content)
      #
      # @param pkcs7_der [String] DER-encoded PKCS#7 signature
      # @param content [String] the original content that was signed
      # @param trust_store [TrustStore] trust store for verification
      # @return [SignatureCheckResult]
      #
      def verify_detached_pkcs7(pkcs7_der, content, trust_store)
        result = SignatureCheckResult.new

        begin
          pkcs7 = OpenSSL::PKCS7.new(pkcs7_der)
          result.signature_parsed = true

          result.certificates = pkcs7.certificates || []
          result.signer_certificate = result.certificates.first

          # For detached signatures, we need to provide the content
          flags = OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::DETACHED

          store = trust_store.store

          if pkcs7.verify(result.certificates, store, content, flags)
            result.signature_valid = true
          else
            result.signature_valid = false
            result.add_error("Detached PKCS#7 signature verification failed")
          end

          extract_signature_info(pkcs7, result)

        rescue OpenSSL::PKCS7::PKCS7Error => e
          result.signature_valid = false
          result.add_error("PKCS#7 error: #{e.message}")
        rescue StandardError => e
          result.signature_valid = false
          result.add_error("Signature verification error: #{e.message}")
        end

        result
      end

      # Verify a raw signature (not PKCS#7 wrapped)
      #
      # @param signature [String] raw signature bytes
      # @param content [String] the signed content
      # @param certificate [OpenSSL::X509::Certificate] signer's certificate
      # @param algorithm [Symbol] signature algorithm used
      # @return [SignatureCheckResult]
      #
      def verify_raw(signature, content, certificate, algorithm: :sha256)
        result = SignatureCheckResult.new
        result.signer_certificate = certificate
        result.certificates = [certificate]

        begin
          public_key = certificate.public_key
          digest = digest_for_algorithm(algorithm)

          if public_key.verify(digest, signature, content)
            result.signature_valid = true
          else
            result.signature_valid = false
            result.add_error("Raw signature verification failed")
          end

          result.signature_algorithm = algorithm

        rescue OpenSSL::PKey::PKeyError => e
          result.signature_valid = false
          result.add_error("Public key error: #{e.message}")
        rescue StandardError => e
          result.signature_valid = false
          result.add_error("Signature verification error: #{e.message}")
        end

        result
      end

      private

      def extract_signature_info(pkcs7, result)
        # Try to extract algorithm info from signers
        signers = pkcs7.signers rescue []
        if signers.any?
          signer = signers.first
          result.signature_algorithm = signer.digest_algorithm.name rescue nil
        end
      end

      def digest_for_algorithm(algorithm)
        case algorithm
        when :sha256, :sha256_rsa, :sha256_ecdsa
          OpenSSL::Digest::SHA256.new
        when :sha384, :sha384_rsa, :sha384_ecdsa
          OpenSSL::Digest::SHA384.new
        when :sha512, :sha512_rsa, :sha512_ecdsa
          OpenSSL::Digest::SHA512.new
        else
          OpenSSL::Digest::SHA256.new
        end
      end
    end

    # Result of signature verification
    class SignatureCheckResult
      attr_accessor :signature_valid, :signature_parsed,
                    :signer_certificate, :certificates,
                    :signature_algorithm, :errors

      def initialize
        @signature_valid = false
        @signature_parsed = false
        @certificates = []
        @errors = []
      end

      def valid?
        signature_valid
      end

      def add_error(msg)
        @errors << msg
      end

      def signer_name
        signer_certificate&.subject&.to_s
      end

      def to_h
        {
          valid: signature_valid,
          parsed: signature_parsed,
          algorithm: signature_algorithm,
          signer: signer_name,
          certificate_count: certificates.size,
          errors: errors
        }
      end
    end
  end
end
