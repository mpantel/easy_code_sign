# frozen_string_literal: true

require "base64"
require "tempfile"
require "easy_code_sign"

module EasySign
  # Service that wraps EasyCodeSign gem for browser extension use
  class SigningService
    def initialize
      configure_easy_code_sign
    end

    # Sign a PDF document
    # @param pdf_data [String] Base64-encoded PDF content
    # @param pin [String] Token PIN
    # @param options [Hash] Signing options
    # @return [Hash] Result with signed PDF data
    def sign(pdf_data:, pin:, options: {})
      # Decode PDF from Base64
      pdf_bytes = Base64.strict_decode64(pdf_data)

      # Write to temp file
      input_file = Tempfile.new(["input", ".pdf"], binmode: true)
      output_file = Tempfile.new(["signed", ".pdf"], binmode: true)

      begin
        input_file.write(pdf_bytes)
        input_file.close

        # Build signing options
        sign_opts = build_sign_options(options).merge(
          pin: pin,
          output_path: output_file.path
        )

        # Sign using EasyCodeSign
        result = EasyCodeSign.sign(input_file.path, **sign_opts)

        # Read signed PDF and encode as Base64
        signed_bytes = File.binread(output_file.path)
        signed_base64 = Base64.strict_encode64(signed_bytes)

        {
          signed_pdf_data: signed_base64,
          signer_name: result.signer_name,
          signed_at: result.signed_at,
          timestamped: result.timestamped?
        }
      ensure
        input_file.unlink
        output_file.close
        output_file.unlink
      end
    end

    # Verify a signed PDF document
    # @param pdf_data [String] Base64-encoded PDF content
    # @param check_timestamp [Boolean] Whether to verify timestamp
    # @return [Hash] Verification result
    def verify(pdf_data:, check_timestamp: true)
      # Decode PDF from Base64
      pdf_bytes = Base64.strict_decode64(pdf_data)

      # Write to temp file
      temp_file = Tempfile.new(["verify", ".pdf"], binmode: true)

      begin
        temp_file.write(pdf_bytes)
        temp_file.close

        # Verify using EasyCodeSign
        result = EasyCodeSign.verify(temp_file.path, check_timestamp: check_timestamp)

        {
          valid: result.valid?,
          signer_name: result.signer_name,
          signer_organization: result.signer_organization,
          signed_at: result.timestamp,
          signature_valid: result.signature_valid?,
          integrity_valid: result.integrity_valid?,
          certificate_valid: result.certificate_valid?,
          chain_valid: result.chain_valid?,
          trusted: result.trusted?,
          timestamped: result.timestamped?,
          timestamp_valid: result.timestamp_valid?,
          errors: result.errors,
          warnings: result.warnings
        }
      ensure
        temp_file.unlink
      end
    end

    # Check if signing is available (token connected, etc.)
    # @return [Hash] Availability status
    def check_availability
      begin
        slots = EasyCodeSign.list_slots

        # Check if any slot has a token present
        token_present = slots.any? { |s| s[:token_present] }

        {
          available: true,
          token_present: token_present,
          slots: slots.map do |slot|
            {
              index: slot[:index],
              token_label: slot[:token_label],
              manufacturer: slot[:manufacturer],
              serial: slot[:serial]
            }
          end
        }
      rescue EasyCodeSign::Pkcs11LibraryError, EasyCodeSign::TokenNotFoundError => e
        {
          available: false,
          token_present: false,
          error: e.message,
          slots: []
        }
      end
    end

    private

    def configure_easy_code_sign
      # Use default configuration - can be customized via env vars or config file
      EasyCodeSign.configure do |config|
        # Provider can be set via env var
        config.provider = ENV.fetch("EASYSIGN_PROVIDER", "safenet").to_sym

        # PKCS#11 library path (auto-detected if not set)
        config.pkcs11_library = ENV["EASYSIGN_PKCS11_LIBRARY"] if ENV["EASYSIGN_PKCS11_LIBRARY"]

        # Timestamp authority
        config.timestamp_authority = ENV.fetch("EASYSIGN_TSA_URL", "http://timestamp.digicert.com")

        # Network timeout
        config.network_timeout = ENV.fetch("EASYSIGN_TIMEOUT", 30).to_i
      end
    end

    def build_sign_options(options)
      opts = {}

      # Timestamp
      opts[:timestamp] = options["timestamp"] || options[:timestamp] || false
      if options["timestampAuthority"] || options[:timestamp_authority]
        EasyCodeSign.configuration.timestamp_authority =
          options["timestampAuthority"] || options[:timestamp_authority]
      end

      # Visible signature
      opts[:visible_signature] = options["visibleSignature"] || options[:visible_signature] || false
      opts[:signature_page] = options["signaturePage"] || options[:signature_page] || 1
      opts[:signature_position] = (options["signaturePosition"] || options[:signature_position] || "bottom_right").to_sym

      # Signature metadata
      opts[:signature_reason] = options["reason"] || options[:reason]
      opts[:signature_location] = options["location"] || options[:location]

      opts.compact
    end
  end
end
