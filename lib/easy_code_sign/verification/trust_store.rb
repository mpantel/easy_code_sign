# frozen_string_literal: true

require "openssl"

module EasyCodeSign
  module Verification
    # Manages trusted root certificates for verification
    #
    # By default, uses the system's trusted CA certificates.
    # Additional certificates can be added for custom PKI.
    #
    # @example Using system trust store
    #   store = TrustStore.new
    #   store.trusted?(certificate, chain)
    #
    # @example Adding custom trusted certificate
    #   store = TrustStore.new
    #   store.add_certificate(my_root_ca)
    #   store.add_file("/path/to/custom_ca.pem")
    #
    class TrustStore
      attr_reader :store

      def initialize(use_system_certs: true)
        @store = OpenSSL::X509::Store.new
        @store.set_default_paths if use_system_certs
        @custom_certs = []
      end

      # Add a trusted certificate
      # @param cert [OpenSSL::X509::Certificate]
      # @return [self]
      def add_certificate(cert)
        @store.add_cert(cert)
        @custom_certs << cert
        self
      rescue OpenSSL::X509::StoreError => e
        # Certificate might already be in store
        raise unless e.message.include?("cert already in hash table")

        self
      end

      # Add certificates from a PEM file
      # @param path [String] path to PEM file
      # @return [self]
      def add_file(path)
        content = File.read(path)
        certs = extract_certificates(content)
        certs.each { |cert| add_certificate(cert) }
        self
      end

      # Add certificates from a directory
      # @param path [String] path to directory containing PEM files
      # @return [self]
      def add_directory(path)
        Dir.glob(File.join(path, "*.pem")).each do |file|
          add_file(file)
        end
        self
      end

      # Check if a certificate is trusted
      # @param cert [OpenSSL::X509::Certificate] certificate to verify
      # @param chain [Array<OpenSSL::X509::Certificate>] intermediate certificates
      # @return [Boolean]
      def trusted?(cert, chain = [])
        @store.verify(cert, chain)
      end

      # Verify and return detailed error if not trusted
      # @param cert [OpenSSL::X509::Certificate]
      # @param chain [Array<OpenSSL::X509::Certificate>]
      # @return [Hash] { trusted: Boolean, error: String|nil }
      def verify(cert, chain = [])
        if @store.verify(cert, chain)
          { trusted: true, error: nil }
        else
          { trusted: false, error: @store.error_string }
        end
      end

      # Get the verification error string from last verify call
      # @return [String, nil]
      def error_string
        @store.error_string
      end

      # Set verification time (for testing signatures against past time)
      # @param time [Time]
      # @return [self]
      def at_time(time)
        @store.time = time
        self
      end

      # Enable/disable CRL checking
      # @param enabled [Boolean]
      # @return [self]
      def check_crl(enabled = true)
        if enabled
          @store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK |
                         OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
        else
          @store.flags = 0
        end
        self
      end

      # Add a CRL for revocation checking
      # @param crl [OpenSSL::X509::CRL]
      # @return [self]
      def add_crl(crl)
        @store.add_crl(crl)
        self
      end

      # Load CRL from file
      # @param path [String] path to CRL file (PEM or DER)
      # @return [self]
      def add_crl_file(path)
        content = File.read(path)
        crl = OpenSSL::X509::CRL.new(content)
        add_crl(crl)
        self
      end

      private

      def extract_certificates(pem_content)
        certs = []
        pem_content.scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m).each do |pem|
          certs << OpenSSL::X509::Certificate.new(pem)
        end
        certs
      end
    end
  end
end
