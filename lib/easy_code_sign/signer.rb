# frozen_string_literal: true

module EasyCodeSign
  # Orchestrates the signing process for different file types
  #
  # @example Sign a gem file
  #   signer = EasyCodeSign::Signer.new
  #   result = signer.sign("my_gem-1.0.0.gem", pin: "1234")
  #
  # @example Sign with timestamp
  #   signer = EasyCodeSign::Signer.new
  #   result = signer.sign("archive.zip", pin: "1234", timestamp: true)
  #
  class Signer
    attr_reader :provider, :configuration

    def initialize(provider: nil, configuration: nil)
      @configuration = configuration || EasyCodeSign.configuration
      @provider = provider || EasyCodeSign.provider
    end

    # Sign a file
    #
    # @param file_path [String] path to file to sign
    # @param pin [String, nil] PIN for hardware token (uses callback if nil)
    # @param output_path [String, nil] output path (defaults to overwriting input)
    # @param timestamp [Boolean] whether to add RFC 3161 timestamp
    # @param algorithm [Symbol] signature algorithm (:sha256_rsa, etc.)
    # @return [SigningResult] result containing signed file path and metadata
    #
    def sign(file_path, pin: nil, output_path: nil, timestamp: nil, algorithm: :sha256_rsa)
      timestamp = configuration.require_timestamp if timestamp.nil?

      signable = create_signable(file_path, output_path: output_path, algorithm: algorithm)
      signable.prepare_for_signing

      provider.with_session(pin: pin) do |session|
        # Get content to sign
        content = signable.content_to_sign

        # Sign with hardware token
        signature = session.sign(content, algorithm: algorithm)

        # Get certificate chain
        certificate_chain = session.certificate_chain

        # Get timestamp if requested
        timestamp_token = nil
        if timestamp
          timestamp_token = request_timestamp(signature)
        end

        # Apply signature to file
        signed_path = signable.apply_signature(signature, certificate_chain, timestamp_token: timestamp_token)

        SigningResult.new(
          file_path: signed_path,
          certificate: certificate_chain.first,
          algorithm: algorithm,
          timestamp_token: timestamp_token,
          signed_at: Time.now
        )
      end
    end

    # Sign multiple files
    #
    # @param file_paths [Array<String>] paths to files to sign
    # @param pin [String, nil] PIN for hardware token
    # @param options [Hash] signing options passed to #sign
    # @return [Array<SigningResult>] results for each file
    #
    def sign_batch(file_paths, pin: nil, **options)
      results = []

      provider.with_session(pin: pin) do |session|
        file_paths.each do |path|
          # Re-use the open session for batch signing
          result = sign_with_session(session, path, **options)
          results << result
        end
      end

      results
    end

    private

    def create_signable(file_path, **options)
      extension = File.extname(file_path).downcase

      case extension
      when ".gem"
        Signable::GemFile.new(file_path, **options)
      when ".zip", ".jar", ".apk", ".war", ".ear"
        Signable::ZipFile.new(file_path, **options)
      else
        raise InvalidFileError, "Unsupported file type: #{extension}. " \
                                "Supported: .gem, .zip, .jar, .apk, .war, .ear"
      end
    end

    def sign_with_session(session, file_path, output_path: nil, timestamp: nil, algorithm: :sha256_rsa)
      timestamp = configuration.require_timestamp if timestamp.nil?

      signable = create_signable(file_path, output_path: output_path, algorithm: algorithm)
      signable.prepare_for_signing

      content = signable.content_to_sign
      signature = session.sign(content, algorithm: algorithm)
      certificate_chain = session.certificate_chain

      timestamp_token = timestamp ? request_timestamp(signature) : nil

      signed_path = signable.apply_signature(signature, certificate_chain, timestamp_token: timestamp_token)

      SigningResult.new(
        file_path: signed_path,
        certificate: certificate_chain.first,
        algorithm: algorithm,
        timestamp_token: timestamp_token,
        signed_at: Time.now
      )
    end

    def request_timestamp(signature)
      return nil unless configuration.timestamp_authority

      client = Timestamp::Client.new(
        configuration.timestamp_authority,
        timeout: configuration.network_timeout
      )

      client.timestamp(
        signature,
        algorithm: configuration.timestamp_hash_algorithm
      )
    end
  end

  # Result of a signing operation
  class SigningResult
    attr_reader :file_path, :certificate, :algorithm, :timestamp_token, :signed_at

    def initialize(file_path:, certificate:, algorithm:, timestamp_token:, signed_at:)
      @file_path = file_path
      @certificate = certificate
      @algorithm = algorithm
      @timestamp_token = timestamp_token
      @signed_at = signed_at
    end

    def timestamped?
      !timestamp_token.nil?
    end

    # Get the timestamp time
    # @return [Time, nil]
    def timestamp
      timestamp_token&.timestamp
    end

    def signer_name
      certificate.subject.to_s
    end

    # Get TSA info if timestamped
    # @return [Hash, nil]
    def timestamp_info
      return nil unless timestamp_token

      timestamp_token.to_h
    end

    def to_h
      {
        file_path: file_path,
        signer: signer_name,
        algorithm: algorithm,
        timestamped: timestamped?,
        timestamp: timestamp_info,
        signed_at: signed_at
      }
    end
  end
end
