# frozen_string_literal: true

require "openssl"
require "net/http"
require "uri"

module EasyCodeSign
  module Verification
    # Validates certificate chains and checks revocation status
    #
    # @example
    #   validator = CertificateChain.new(trust_store)
    #   result = validator.validate(cert, intermediates)
    #
    class CertificateChain
      attr_reader :trust_store

      def initialize(trust_store, check_revocation: false, network_timeout: 10)
        @trust_store = trust_store
        @check_revocation = check_revocation
        @network_timeout = network_timeout
      end

      # Validate a certificate chain
      #
      # @param certificate [OpenSSL::X509::Certificate] end-entity certificate
      # @param intermediates [Array<OpenSSL::X509::Certificate>] intermediate certs
      # @param at_time [Time, nil] verify at specific time (nil = now)
      # @return [ChainValidationResult]
      #
      def validate(certificate, intermediates = [], at_time: nil)
        result = ChainValidationResult.new
        result.certificate = certificate

        # Set verification time if specified
        if at_time
          trust_store.at_time(at_time)
        end

        # Build the chain
        chain = build_chain(certificate, intermediates)
        result.chain = chain

        # Verify basic certificate validity
        validate_certificate(certificate, result, at_time)

        # Verify chain to trusted root
        validate_chain_trust(certificate, chain, result)

        # Check revocation if enabled
        if @check_revocation && result.chain_valid
          check_revocation_status(certificate, chain, result)
        end

        # Check code signing extended key usage
        check_key_usage(certificate, result)

        result.valid = result.certificate_valid && result.chain_valid &&
                       result.trusted && result.not_revoked

        result
      end

      private

      def build_chain(leaf, intermediates)
        chain = [leaf]
        current = leaf
        remaining = intermediates.dup

        # Build chain by matching issuer -> subject
        loop do
          issuer = remaining.find { |c| c.subject.to_s == current.issuer.to_s }
          break unless issuer

          chain << issuer
          remaining.delete(issuer)
          current = issuer

          # Stop if self-signed (root)
          break if current.subject.to_s == current.issuer.to_s
        end

        chain
      end

      def validate_certificate(cert, result, at_time)
        check_time = at_time || Time.now

        # Check not before
        if check_time < cert.not_before
          result.add_error("Certificate not yet valid (starts #{cert.not_before})")
          result.certificate_valid = false
          return
        end

        # Check not after
        if check_time > cert.not_after
          result.add_error("Certificate expired (#{cert.not_after})")
          result.expired = true
          result.certificate_valid = false
          return
        end

        result.certificate_valid = true
        result.expires_at = cert.not_after

        # Warn if expiring soon (30 days)
        days_until_expiry = (cert.not_after - Time.now) / 86_400
        if days_until_expiry < 30 && days_until_expiry > 0
          result.add_warning("Certificate expires in #{days_until_expiry.to_i} days")
        end
      end

      def validate_chain_trust(cert, chain, result)
        # Remove leaf cert from chain for verification
        intermediates = chain[1..] || []

        verification = trust_store.verify(cert, intermediates)

        if verification[:trusted]
          result.chain_valid = true
          result.trusted = true
        else
          result.chain_valid = false
          result.trusted = false
          result.add_error("Certificate chain validation failed: #{verification[:error]}")
        end
      end

      def check_revocation_status(cert, chain, result)
        result.revocation_checked = true

        # Try OCSP first (faster, real-time)
        ocsp_result = check_ocsp(cert, chain)
        if ocsp_result
          if ocsp_result[:revoked]
            result.not_revoked = false
            result.add_error("Certificate has been revoked (OCSP)")
          else
            result.not_revoked = true
          end
          return
        end

        # Fall back to CRL if OCSP unavailable
        crl_result = check_crl(cert, chain)
        if crl_result
          if crl_result[:revoked]
            result.not_revoked = false
            result.add_error("Certificate has been revoked (CRL)")
          else
            result.not_revoked = true
          end
        else
          result.add_warning("Could not check revocation status")
        end
      end

      def check_ocsp(cert, chain)
        # Find OCSP responder URL from certificate
        ocsp_uri = extract_ocsp_uri(cert)
        return nil unless ocsp_uri

        issuer = chain[1] # Issuer is second in chain
        return nil unless issuer

        begin
          # Build OCSP request
          digest = OpenSSL::Digest.new("SHA256")
          cert_id = OpenSSL::OCSP::CertificateId.new(cert, issuer, digest)
          request = OpenSSL::OCSP::Request.new
          request.add_certid(cert_id)
          request.add_nonce

          # Send request
          uri = URI.parse(ocsp_uri)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = (uri.scheme == "https")
          http.open_timeout = @network_timeout
          http.read_timeout = @network_timeout

          http_request = Net::HTTP::Post.new(uri.path)
          http_request["Content-Type"] = "application/ocsp-request"
          http_request.body = request.to_der

          response = http.request(http_request)
          return nil unless response.is_a?(Net::HTTPSuccess)

          ocsp_response = OpenSSL::OCSP::Response.new(response.body)
          return nil unless ocsp_response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL

          basic = ocsp_response.basic
          return nil unless basic

          # Check certificate status
          status, = basic.status.find { |s| s[0].cmp(cert_id) }
          return nil unless status

          { revoked: status[1] == OpenSSL::OCSP::V_CERTSTATUS_REVOKED }
        rescue StandardError
          nil
        end
      end

      def check_crl(cert, chain)
        crl_uri = extract_crl_uri(cert)
        return nil unless crl_uri

        begin
          uri = URI.parse(crl_uri)
          response = Net::HTTP.get_response(uri)
          return nil unless response.is_a?(Net::HTTPSuccess)

          crl = OpenSSL::X509::CRL.new(response.body)

          # Check if certificate is in CRL
          revoked = crl.revoked.any? { |r| r.serial == cert.serial }
          { revoked: revoked }
        rescue StandardError
          nil
        end
      end

      def extract_ocsp_uri(cert)
        aia = cert.extensions.find { |e| e.oid == "authorityInfoAccess" }
        return nil unless aia

        match = aia.value.match(/OCSP - URI:(\S+)/)
        match ? match[1] : nil
      end

      def extract_crl_uri(cert)
        cdp = cert.extensions.find { |e| e.oid == "crlDistributionPoints" }
        return nil unless cdp

        match = cdp.value.match(/URI:(\S+)/)
        match ? match[1] : nil
      end

      def check_key_usage(cert, result)
        # Check for code signing EKU
        eku = cert.extensions.find { |e| e.oid == "extendedKeyUsage" }

        if eku
          unless eku.value.include?("Code Signing")
            result.add_warning("Certificate does not have Code Signing extended key usage")
          end
        else
          result.add_warning("Certificate has no extended key usage extension")
        end
      end
    end

    # Result of certificate chain validation
    class ChainValidationResult
      attr_accessor :valid, :certificate, :chain,
                    :certificate_valid, :chain_valid, :trusted,
                    :not_revoked, :revocation_checked, :expired,
                    :expires_at, :errors, :warnings

      def initialize
        @valid = false
        @certificate_valid = false
        @chain_valid = false
        @trusted = false
        @not_revoked = true
        @revocation_checked = false
        @expired = false
        @errors = []
        @warnings = []
      end

      def add_error(msg)
        @errors << msg
      end

      def add_warning(msg)
        @warnings << msg
      end

      def to_h
        {
          valid: valid,
          certificate_valid: certificate_valid,
          chain_valid: chain_valid,
          trusted: trusted,
          not_revoked: not_revoked,
          revocation_checked: revocation_checked,
          expired: expired,
          expires_at: expires_at&.iso8601,
          errors: errors,
          warnings: warnings
        }
      end
    end
  end
end
