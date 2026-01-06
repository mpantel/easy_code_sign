# frozen_string_literal: true

module EasyCodeSign
  module Providers
    # Abstract base class for hardware token providers
    #
    # Subclasses must implement:
    # - #connect - Establish connection to the token
    # - #disconnect - Close connection to the token
    # - #login(pin) - Authenticate with PIN
    # - #logout - End authenticated session
    # - #sign(data, algorithm:) - Sign data with the private key
    # - #certificate - Return the signing certificate
    # - #certificate_chain - Return the full certificate chain
    #
    class Base
      attr_reader :configuration

      def initialize(configuration)
        @configuration = configuration
        @connected = false
        @logged_in = false
      end

      # Connect to the hardware token
      # @raise [TokenNotFoundError] if token is not connected
      # @return [void]
      def connect
        raise NotImplementedError, "#{self.class}#connect must be implemented"
      end

      # Disconnect from the hardware token
      # @return [void]
      def disconnect
        raise NotImplementedError, "#{self.class}#disconnect must be implemented"
      end

      # Authenticate with PIN
      # @param pin [String] the PIN for the token
      # @raise [PinError] if PIN is incorrect
      # @raise [TokenLockedError] if token is locked
      # @return [void]
      def login(pin)
        raise NotImplementedError, "#{self.class}#login must be implemented"
      end

      # End authenticated session
      # @return [void]
      def logout
        raise NotImplementedError, "#{self.class}#logout must be implemented"
      end

      # Sign data using the private key on the token
      # @param data [String] the data to sign (typically a hash)
      # @param algorithm [Symbol] signature algorithm (:sha256_rsa, :sha384_rsa, :sha512_rsa, etc.)
      # @raise [SignatureGenerationError] if signing fails
      # @return [String] the raw signature bytes
      def sign(data, algorithm:)
        raise NotImplementedError, "#{self.class}#sign must be implemented"
      end

      # Get the signing certificate from the token
      # @raise [KeyNotFoundError] if no certificate is found
      # @return [OpenSSL::X509::Certificate]
      def certificate
        raise NotImplementedError, "#{self.class}#certificate must be implemented"
      end

      # Get the full certificate chain from the token
      # @return [Array<OpenSSL::X509::Certificate>] certificates ordered from leaf to root
      def certificate_chain
        raise NotImplementedError, "#{self.class}#certificate_chain must be implemented"
      end

      # Check if connected to the token
      # @return [Boolean]
      def connected?
        @connected
      end

      # Check if authenticated (logged in)
      # @return [Boolean]
      def logged_in?
        @logged_in
      end

      # List available slots/tokens
      # @return [Array<Hash>] array of slot information hashes
      def list_slots
        raise NotImplementedError, "#{self.class}#list_slots must be implemented"
      end

      # Execute a block with automatic connect/login/logout/disconnect
      # @param pin [String, nil] PIN for authentication (uses callback if nil)
      # @yield [provider] yields self to the block
      # @return [Object] result of the block
      def with_session(pin: nil)
        pin ||= request_pin
        connect
        login(pin)
        yield self
      ensure
        logout if logged_in?
        disconnect if connected?
      end

      protected

      def log(level, message)
        return unless configuration.logger

        configuration.logger.send(level, "[EasyCodeSign] #{message}")
      end

      private

      def request_pin
        callback = configuration.pin_callback
        raise ConfigurationError, "No PIN provided and no pin_callback configured" unless callback

        slot_info = { slot_index: configuration.slot_index }
        callback.call(slot_info)
      end
    end
  end
end
