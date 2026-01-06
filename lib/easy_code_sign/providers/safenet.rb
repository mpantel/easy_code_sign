# frozen_string_literal: true

module EasyCodeSign
  module Providers
    # SafeNet eToken provider
    #
    # Implements PKCS#11 integration for SafeNet eToken hardware security tokens.
    # These tokens are commonly used for code signing certificates.
    #
    # @example
    #   provider = EasyCodeSign::Providers::Safenet.new(config)
    #   provider.with_session(pin: "1234") do |p|
    #     signature = p.sign(digest, algorithm: :sha256_rsa)
    #   end
    #
    class Safenet < Pkcs11Base
      # Default PKCS#11 library paths for SafeNet tokens
      DEFAULT_LIBRARY_PATHS = {
        darwin: [
          "/usr/local/lib/libeToken.dylib",
          "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib"
        ],
        linux: [
          "/usr/lib/libeToken.so",
          "/usr/lib/x86_64-linux-gnu/libeToken.so",
          "/opt/safenet/eToken/lib/libeToken.so"
        ],
        windows: [
          "C:\\Windows\\System32\\eToken.dll",
          "C:\\Program Files\\SafeNet\\Authentication\\eToken PKI Client\\x64\\eToken.dll"
        ]
      }.freeze

      def initialize(configuration)
        super
        auto_detect_library! if configuration.pkcs11_library.nil?
      end

      # SafeNet tokens may require specific initialization
      def connect
        log :info, "Connecting to SafeNet eToken"
        super
        log :info, "Connected to SafeNet eToken: #{token_label}"
      end

      # Get the token label/name
      # @return [String]
      def token_label
        return nil unless @slot

        @slot.token_info.label.strip
      rescue PKCS11::Error
        nil
      end

      # Get token serial number
      # @return [String]
      def serial_number
        return nil unless @slot

        @slot.token_info.serial_number.strip
      rescue PKCS11::Error
        nil
      end

      # Check if token requires PIN change
      # @return [Boolean]
      def pin_change_required?
        return false unless @slot

        flags = @slot.token_info.flags
        (flags & PKCS11::CKF_USER_PIN_TO_BE_CHANGED) != 0
      rescue PKCS11::Error
        false
      end

      private

      def auto_detect_library!
        platform = detect_platform
        paths = DEFAULT_LIBRARY_PATHS[platform] || []

        found = paths.find { |path| File.exist?(path) }

        if found
          log :debug, "Auto-detected SafeNet library: #{found}"
          configuration.pkcs11_library = found
        else
          raise ConfigurationError,
                "SafeNet PKCS#11 library not found. Searched: #{paths.join(', ')}. " \
                "Please set pkcs11_library explicitly."
        end
      end

      def detect_platform
        case RUBY_PLATFORM
        when /darwin/
          :darwin
        when /linux/
          :linux
        when /mswin|mingw/
          :windows
        else
          :linux # Default fallback
        end
      end
    end
  end
end
