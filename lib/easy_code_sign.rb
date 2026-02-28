# frozen_string_literal: true

require_relative "easy_code_sign/version"
require_relative "easy_code_sign/errors"
require_relative "easy_code_sign/configuration"
require_relative "easy_code_sign/providers/base"
require_relative "easy_code_sign/providers/pkcs11_base"
require_relative "easy_code_sign/providers/safenet"
require_relative "easy_code_sign/signable/base"
require_relative "easy_code_sign/signable/gem_file"
require_relative "easy_code_sign/signable/zip_file"
require_relative "easy_code_sign/signable/pdf_file"
require_relative "easy_code_sign/pdf/timestamp_handler"
require_relative "easy_code_sign/pdf/appearance_builder"
require_relative "easy_code_sign/timestamp/request"
require_relative "easy_code_sign/timestamp/response"
require_relative "easy_code_sign/timestamp/client"
require_relative "easy_code_sign/timestamp/verifier"
require_relative "easy_code_sign/verification/result"
require_relative "easy_code_sign/verification/trust_store"
require_relative "easy_code_sign/verification/certificate_chain"
require_relative "easy_code_sign/verification/signature_checker"
require_relative "easy_code_sign/deferred_signing_request"
require_relative "easy_code_sign/signer"
require_relative "easy_code_sign/verifier"

module EasyCodeSign
  class << self
    # Get the current configuration
    # @return [Configuration]
    def configuration
      @configuration ||= Configuration.new
    end

    # Configure EasyCodeSign
    # @yield [Configuration] the configuration object
    # @return [Configuration]
    def configure
      yield(configuration)
      configuration
    end

    # Reset configuration to defaults
    # @return [Configuration]
    def reset_configuration!
      @configuration = Configuration.new
    end

    # Get a provider instance based on current configuration
    # @return [Providers::Base] a provider instance
    def provider
      @provider ||= build_provider
    end

    # Reset the cached provider instance
    # @return [void]
    def reset_provider!
      @provider = nil
    end

    # Sign a file using the configured provider
    #
    # @param file_path [String] path to the file to sign
    # @param pin [String, nil] PIN for the token (uses callback if nil)
    # @param output_path [String, nil] output path for signed file
    # @param timestamp [Boolean] whether to add timestamp (default: from config)
    # @param algorithm [Symbol] signature algorithm (default: :sha256_rsa)
    # @return [SigningResult] signing result with file path and metadata
    #
    # @example Sign a gem
    #   EasyCodeSign.sign("my_gem-1.0.0.gem", pin: "1234")
    #
    # @example Sign with timestamp
    #   EasyCodeSign.sign("archive.zip", pin: "1234", timestamp: true)
    #
    def sign(file_path, pin: nil, output_path: nil, timestamp: nil, algorithm: :sha256_rsa)
      signer = Signer.new
      signer.sign(file_path, pin: pin, output_path: output_path, timestamp: timestamp, algorithm: algorithm)
    end

    # Verify a signed file
    #
    # @param file_path [String] path to the signed file
    # @param check_timestamp [Boolean] whether to verify timestamp (default: true)
    # @param trust_store [Verification::TrustStore, nil] custom trust store
    # @return [Verification::Result] verification result
    #
    # @example Verify a signed gem
    #   result = EasyCodeSign.verify("signed.gem")
    #   puts result.valid? ? "Valid!" : result.errors.join(", ")
    #
    def verify(file_path, check_timestamp: true, trust_store: nil)
      verifier = Verifier.new(trust_store: trust_store)
      verifier.verify(file_path, check_timestamp: check_timestamp)
    end

    # Phase 1 of deferred PDF signing.
    # Prepares a PDF with placeholder signature and returns a DeferredSigningRequest
    # containing the digest to be signed by an external signer (Fortify, WebCrypto, etc.).
    #
    # @param file_path [String] path to the PDF
    # @param pin [String, nil] PIN for hardware token (needed for certificate retrieval)
    # @param digest_algorithm [String] "sha256", "sha384", or "sha512"
    # @param timestamp [Boolean] whether to reserve timestamp space
    # @return [DeferredSigningRequest]
    #
    # @example
    #   request = EasyCodeSign.prepare_pdf("document.pdf", pin: "1234")
    #   request.digest_base64 #=> "abc123..."  (send to external signer)
    #
    def prepare_pdf(file_path, pin: nil, digest_algorithm: "sha256", timestamp: false, **extra_options)
      signer = Signer.new
      signer.prepare_pdf(file_path, pin: pin, digest_algorithm: digest_algorithm,
                                    timestamp: timestamp, **extra_options)
    end

    # Phase 2 of deferred PDF signing.
    # Embeds an externally-produced raw signature into the prepared PDF.
    #
    # @param deferred_request [DeferredSigningRequest] from prepare_pdf
    # @param raw_signature [String] raw signature bytes from external signer
    # @return [SigningResult]
    #
    # @example
    #   result = EasyCodeSign.finalize_pdf(request, raw_signature)
    #   result.file_path #=> "document_prepared.pdf"
    #
    def finalize_pdf(deferred_request, raw_signature, **options)
      signer = Signer.new
      signer.finalize_pdf(deferred_request, raw_signature, **options)
    end

    # Create a verifier instance for batch operations
    # @param trust_store [Verification::TrustStore, nil]
    # @return [Verifier]
    def verifier(trust_store: nil)
      Verifier.new(trust_store: trust_store)
    end

    # List available token slots
    # @return [Array<Hash>] array of slot information
    def list_slots
      provider.list_slots
    end

    # Create a signer instance for batch operations
    # @return [Signer]
    def signer
      Signer.new
    end

    # Detect file type and return appropriate signable handler
    # @param file_path [String] path to file
    # @return [Signable::Base] signable handler
    def signable_for(file_path, **options)
      extension = File.extname(file_path).downcase

      case extension
      when ".gem"
        Signable::GemFile.new(file_path, **options)
      when ".zip", ".jar", ".apk", ".war", ".ear"
        Signable::ZipFile.new(file_path, **options)
      when ".pdf"
        Signable::PdfFile.new(file_path, **options)
      else
        raise InvalidFileError, "Unsupported file type: #{extension}"
      end
    end

    private

    def build_provider
      configuration.validate!

      case configuration.provider
      when :safenet
        Providers::Safenet.new(configuration)
      else
        raise ConfigurationError, "Unknown provider: #{configuration.provider}"
      end
    end
  end
end
