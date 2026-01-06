# frozen_string_literal: true

module EasyCodeSign
  module Verification
    # Comprehensive result of signature verification
    #
    # Provides detailed information about each aspect of verification:
    # - Signature validity (cryptographic check)
    # - Certificate chain validity
    # - Trust status (chains to trusted root)
    # - Timestamp validity (if present)
    # - File integrity (content hasn't been modified)
    #
    # @example
    #   result = EasyCodeSign.verify("signed.gem")
    #   if result.valid?
    #     puts "Signed by: #{result.signer_name}"
    #     puts "Signed at: #{result.timestamp}" if result.timestamped?
    #   else
    #     puts "Verification failed:"
    #     result.errors.each { |e| puts "  - #{e}" }
    #   end
    #
    class Result
      # Overall verification status
      attr_accessor :valid

      # Individual check results
      attr_accessor :signature_valid,    # Cryptographic signature is valid
                    :integrity_valid,    # File content matches signature
                    :certificate_valid,  # Certificate is valid (not expired, etc.)
                    :chain_valid,        # Certificate chain is complete
                    :trusted,            # Chain leads to trusted root
                    :timestamp_valid,    # Timestamp is valid (if present)
                    :not_revoked         # Certificate not revoked (if checked)

      # Signer information
      attr_accessor :signer_certificate, # The signing certificate
                    :certificate_chain,  # Full chain from signer to root
                    :signer_name,        # CN from certificate
                    :signer_organization # O from certificate

      # Timestamp information
      attr_accessor :timestamped,        # Whether timestamp is present
                    :timestamp,          # Time from timestamp token
                    :timestamp_authority # TSA name/URL

      # Detailed messages
      attr_accessor :errors,   # Array of error messages
                    :warnings  # Array of warning messages

      # File information
      attr_accessor :file_path,
                    :file_type,      # :gem, :zip, etc.
                    :signature_algorithm

      def initialize
        @valid = false
        @signature_valid = false
        @integrity_valid = false
        @certificate_valid = false
        @chain_valid = false
        @trusted = false
        @timestamp_valid = false
        @not_revoked = true  # Assume not revoked unless checked
        @timestamped = false
        @errors = []
        @warnings = []
      end

      # Overall validity check
      # @return [Boolean]
      def valid?
        valid
      end

      # Check if signature is cryptographically valid
      # @return [Boolean]
      def signature_valid?
        signature_valid
      end

      # Check if file integrity is intact
      # @return [Boolean]
      def integrity_valid?
        integrity_valid
      end

      # Check if certificate is valid
      # @return [Boolean]
      def certificate_valid?
        certificate_valid
      end

      # Check if certificate chain is valid
      # @return [Boolean]
      def chain_valid?
        chain_valid
      end

      # Check if signing certificate is trusted
      # @return [Boolean]
      def trusted?
        trusted
      end

      # Check if timestamp is present
      # @return [Boolean]
      def timestamped?
        timestamped
      end

      # Check if timestamp is valid
      # @return [Boolean]
      def timestamp_valid?
        timestamp_valid
      end

      # Check if certificate revocation was verified
      # @return [Boolean]
      def revocation_checked?
        @revocation_checked || false
      end

      attr_writer :revocation_checked

      # Get certificate expiration date
      # @return [Time, nil]
      def certificate_expires_at
        signer_certificate&.not_after
      end

      # Check if certificate is currently expired
      # @return [Boolean]
      def certificate_expired?
        return false unless signer_certificate

        signer_certificate.not_after < Time.now
      end

      # Check if certificate was valid at signing time (requires timestamp)
      # @return [Boolean, nil] nil if no timestamp
      def certificate_valid_at_signing?
        return nil unless timestamped? && timestamp && signer_certificate

        timestamp >= signer_certificate.not_before &&
          timestamp <= signer_certificate.not_after
      end

      # Add an error message
      # @param message [String]
      def add_error(message)
        errors << message
      end

      # Add a warning message
      # @param message [String]
      def add_warning(message)
        warnings << message
      end

      # Convert to hash for serialization
      # @return [Hash]
      def to_h
        {
          valid: valid,
          file_path: file_path,
          file_type: file_type,
          checks: {
            signature_valid: signature_valid,
            integrity_valid: integrity_valid,
            certificate_valid: certificate_valid,
            chain_valid: chain_valid,
            trusted: trusted,
            timestamp_valid: timestamp_valid,
            not_revoked: not_revoked
          },
          signer: {
            name: signer_name,
            organization: signer_organization,
            certificate_expires: certificate_expires_at&.iso8601
          },
          timestamp: timestamped ? {
            time: timestamp&.iso8601,
            authority: timestamp_authority,
            valid: timestamp_valid
          } : nil,
          errors: errors,
          warnings: warnings
        }
      end

      # Human-readable summary
      # @return [String]
      def summary
        status = valid? ? "VALID" : "INVALID"
        lines = ["Signature: #{status}"]

        if signer_name
          lines << "Signer: #{signer_name}"
          lines << "Organization: #{signer_organization}" if signer_organization
        end

        if timestamped?
          lines << "Timestamp: #{timestamp&.iso8601} (#{timestamp_valid? ? 'valid' : 'invalid'})"
        end

        unless errors.empty?
          lines << "Errors:"
          errors.each { |e| lines << "  - #{e}" }
        end

        unless warnings.empty?
          lines << "Warnings:"
          warnings.each { |w| lines << "  - #{w}" }
        end

        lines.join("\n")
      end
    end
  end
end
