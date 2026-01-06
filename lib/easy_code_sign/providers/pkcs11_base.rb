# frozen_string_literal: true

require "pkcs11"
require "openssl"

module EasyCodeSign
  module Providers
    # Base class for PKCS#11-based token providers
    #
    # Provides common functionality for tokens that use the PKCS#11 interface.
    # Subclasses can override methods to handle token-specific behavior.
    #
    class Pkcs11Base < Base
      # PKCS#11 mechanism mappings for signature algorithms
      SIGNATURE_MECHANISMS = {
        sha256_rsa: :CKM_SHA256_RSA_PKCS,
        sha384_rsa: :CKM_SHA384_RSA_PKCS,
        sha512_rsa: :CKM_SHA512_RSA_PKCS,
        sha256_ecdsa: :CKM_ECDSA_SHA256,
        sha384_ecdsa: :CKM_ECDSA_SHA384,
        sha512_ecdsa: :CKM_ECDSA_SHA512
      }.freeze

      def initialize(configuration)
        super
        @pkcs11 = nil
        @session = nil
        @slot = nil
      end

      def connect
        log :debug, "Loading PKCS#11 library: #{configuration.pkcs11_library}"
        @pkcs11 = PKCS11.open(configuration.pkcs11_library)

        slots = available_slots
        raise TokenNotFoundError, "No tokens found in any slot" if slots.empty?

        @slot = slots[configuration.slot_index]
        raise TokenNotFoundError, "Slot #{configuration.slot_index} not found" unless @slot

        log :debug, "Opening session on slot #{configuration.slot_index}"
        @session = @slot.open(PKCS11::CKF_SERIAL_SESSION | PKCS11::CKF_RW_SESSION)
        @connected = true
      rescue PKCS11::Error => e
        raise Pkcs11Error.new("Failed to connect: #{e.message}", pkcs11_error_code: e.error_code)
      end

      def disconnect
        return unless @connected

        log :debug, "Closing PKCS#11 session"
        @session&.close
        @pkcs11&.close
        @session = nil
        @pkcs11 = nil
        @slot = nil
        @connected = false
      rescue PKCS11::Error => e
        log :warn, "Error during disconnect: #{e.message}"
      end

      def login(pin)
        raise TokenNotFoundError, "Not connected to token" unless @connected

        log :debug, "Logging in to token"
        @session.login(:USER, pin)
        @logged_in = true
      rescue PKCS11::Error => e
        handle_login_error(e)
      end

      def logout
        return unless @logged_in

        log :debug, "Logging out from token"
        @session&.logout
        @logged_in = false
      rescue PKCS11::Error => e
        log :warn, "Error during logout: #{e.message}"
        @logged_in = false
      end

      def sign(data, algorithm: :sha256_rsa)
        raise TokenNotFoundError, "Not logged in" unless @logged_in

        mechanism = SIGNATURE_MECHANISMS[algorithm]
        raise SigningError, "Unsupported algorithm: #{algorithm}" unless mechanism

        private_key = find_private_key
        raise KeyNotFoundError, "No private key found on token" unless private_key

        log :debug, "Signing #{data.bytesize} bytes with #{algorithm}"
        @session.sign(mechanism, private_key, data)
      rescue PKCS11::Error => e
        raise SignatureGenerationError, "Signing failed: #{e.message}"
      end

      def certificate
        @certificate ||= find_certificate
      end

      def certificate_chain
        @certificate_chain ||= build_certificate_chain
      end

      def list_slots
        @pkcs11 ||= PKCS11.open(configuration.pkcs11_library)
        @pkcs11.slots.map.with_index do |slot, index|
          token_info = begin
            slot.token_info
          rescue StandardError
            nil
          end

          {
            index: index,
            description: slot.info.slot_description.strip,
            token_present: token_info != nil,
            token_label: token_info&.label&.strip,
            manufacturer: token_info&.manufacturer_id&.strip,
            serial: token_info&.serial_number&.strip
          }
        end
      end

      protected

      def available_slots
        @pkcs11.slots.select do |slot|
          slot.token_info rescue false # Returns false if no token present
        end
      end

      def find_private_key
        @session.find_objects(CKA_CLASS: PKCS11::CKO_PRIVATE_KEY).first
      end

      def find_certificate
        cert_obj = @session.find_objects(CKA_CLASS: PKCS11::CKO_CERTIFICATE).first
        raise KeyNotFoundError, "No certificate found on token" unless cert_obj

        cert_der = @session.get_attribute_value(cert_obj, :CKA_VALUE).first
        OpenSSL::X509::Certificate.new(cert_der)
      end

      def build_certificate_chain
        certs = @session.find_objects(CKA_CLASS: PKCS11::CKO_CERTIFICATE).map do |cert_obj|
          cert_der = @session.get_attribute_value(cert_obj, :CKA_VALUE).first
          OpenSSL::X509::Certificate.new(cert_der)
        end

        # Sort chain: leaf first, then intermediates, then root
        sort_certificate_chain(certs)
      end

      def sort_certificate_chain(certs)
        return certs if certs.size <= 1

        # Find the leaf certificate (not an issuer of any other cert)
        issuers = certs.map(&:subject).map(&:to_s)
        leaf = certs.find { |c| !issuers.include?(c.issuer.to_s) || c.subject == c.issuer }

        return certs unless leaf

        # Build chain from leaf
        chain = [leaf]
        remaining = certs - [leaf]

        while remaining.any?
          current = chain.last
          issuer = remaining.find { |c| c.subject.to_s == current.issuer.to_s }
          break unless issuer

          chain << issuer
          remaining.delete(issuer)
        end

        chain
      end

      private

      def handle_login_error(error)
        case error.error_code
        when PKCS11::CKR_PIN_INCORRECT
          raise PinError, "Incorrect PIN"
        when PKCS11::CKR_PIN_LOCKED
          raise TokenLockedError, "Token is locked due to too many failed PIN attempts"
        when PKCS11::CKR_PIN_EXPIRED
          raise PinError, "PIN has expired and must be changed"
        else
          raise Pkcs11Error.new("Login failed: #{error.message}", pkcs11_error_code: error.error_code)
        end
      end
    end
  end
end
