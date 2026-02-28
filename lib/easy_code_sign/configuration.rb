# frozen_string_literal: true

module EasyCodeSign
  # Global configuration for EasyCodeSign
  #
  # @example Configure the gem
  #   EasyCodeSign.configure do |config|
  #     config.provider = :safenet
  #     config.pkcs11_library = '/usr/local/lib/libeToken.dylib'
  #     config.timestamp_authority = 'http://timestamp.digicert.com'
  #   end
  #
  class Configuration
    # Token provider type (:safenet, :yubikey, etc.)
    # @return [Symbol]
    attr_accessor :provider

    # Path to the PKCS#11 library for the hardware token
    # @return [String, nil]
    attr_accessor :pkcs11_library

    # Token slot index (default: 0)
    # @return [Integer]
    attr_accessor :slot_index

    # RFC 3161 Timestamp Authority URL
    # @return [String, nil]
    attr_accessor :timestamp_authority

    # Hash algorithm for timestamping (:sha256, :sha384, :sha512)
    # @return [Symbol]
    attr_accessor :timestamp_hash_algorithm

    # Whether to require timestamping for all signatures
    # @return [Boolean]
    attr_accessor :require_timestamp

    # Custom trust store path for verification
    # @return [String, nil]
    attr_accessor :trust_store_path

    # Whether to check certificate revocation during verification
    # @return [Boolean]
    attr_accessor :check_revocation

    # Timeout for network operations (TSA, OCSP) in seconds
    # @return [Integer]
    attr_accessor :network_timeout

    # Logger instance for debugging
    # @return [Logger, nil]
    attr_accessor :logger

    # Callback for PIN entry (receives slot_info, returns PIN string)
    # @return [Proc, nil]
    attr_accessor :pin_callback

    def initialize
      @provider = :safenet
      @pkcs11_library = default_pkcs11_library
      @slot_index = 0
      @timestamp_authority = ENV["EASYSIGN_TSA_URL"]
      @timestamp_hash_algorithm = :sha256
      @require_timestamp = false
      @trust_store_path = nil
      @check_revocation = true
      @network_timeout = 30
      @logger = nil
      @pin_callback = nil
    end

    # Validates the configuration
    # @raise [ConfigurationError] if configuration is invalid
    def validate!
      raise ConfigurationError, "Provider must be specified" if provider.nil?
      raise ConfigurationError, "PKCS#11 library path must be specified" if pkcs11_library.nil?

      unless File.exist?(pkcs11_library)
        raise ConfigurationError, "PKCS#11 library not found: #{pkcs11_library}"
      end

      if require_timestamp && timestamp_authority.nil?
        raise ConfigurationError, "Timestamp authority URL required when require_timestamp is true"
      end

      true
    end

    private

    def default_pkcs11_library
      case RUBY_PLATFORM
      when /darwin/
        "/usr/local/lib/libeToken.dylib"
      when /linux/
        "/usr/lib/libeToken.so"
      when /mswin|mingw/
        "C:\\Windows\\System32\\eToken.dll"
      end
    end
  end
end
