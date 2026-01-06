# frozen_string_literal: true

module EasyCodeSign
  module Signable
    # Abstract base class for signable file types
    #
    # Subclasses must implement:
    # - #prepare_for_signing - Extract/prepare content for signing
    # - #apply_signature(signature, certificate_chain) - Embed signature in file
    # - #extract_signature - Extract existing signature for verification
    # - #content_to_sign - Return the bytes to be signed
    #
    class Base
      attr_reader :file_path, :options

      def initialize(file_path, **options)
        @file_path = File.expand_path(file_path)
        @options = options
        validate_file!
      end

      # Prepare content for signing
      # @return [void]
      def prepare_for_signing
        raise NotImplementedError, "#{self.class}#prepare_for_signing must be implemented"
      end

      # Get the content that will be signed (typically a hash of the file)
      # @return [String] bytes to be signed
      def content_to_sign
        raise NotImplementedError, "#{self.class}#content_to_sign must be implemented"
      end

      # Apply signature to the file
      # @param signature [String] raw signature bytes
      # @param certificate_chain [Array<OpenSSL::X509::Certificate>] signing certificate chain
      # @param timestamp_token [String, nil] optional RFC 3161 timestamp token
      # @return [String] path to the signed output file
      def apply_signature(signature, certificate_chain, timestamp_token: nil)
        raise NotImplementedError, "#{self.class}#apply_signature must be implemented"
      end

      # Extract existing signature from the file
      # @return [Hash, nil] signature data or nil if unsigned
      def extract_signature
        raise NotImplementedError, "#{self.class}#extract_signature must be implemented"
      end

      # Check if file is already signed
      # @return [Boolean]
      def signed?
        !extract_signature.nil?
      end

      # Get the hash algorithm to use
      # @return [Symbol] :sha256, :sha384, or :sha512
      def hash_algorithm
        options.fetch(:hash_algorithm, :sha256)
      end

      # Compute hash of data using configured algorithm
      # @param data [String] data to hash
      # @return [String] hash bytes
      def compute_hash(data)
        digest_class.digest(data)
      end

      # Get the OpenSSL digest class for the hash algorithm
      # @return [Class]
      def digest_class
        case hash_algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        else raise ArgumentError, "Unsupported hash algorithm: #{hash_algorithm}"
        end
      end

      # Get signature algorithm symbol for the provider
      # @param key_type [Symbol] :rsa or :ecdsa
      # @return [Symbol]
      def signature_algorithm(key_type = :rsa)
        :"#{hash_algorithm}_#{key_type}"
      end

      protected

      def validate_file!
        raise InvalidFileError, "File not found: #{file_path}" unless File.exist?(file_path)
        raise InvalidFileError, "Cannot read file: #{file_path}" unless File.readable?(file_path)
      end

      def output_path
        options[:output_path] || file_path
      end
    end
  end
end
