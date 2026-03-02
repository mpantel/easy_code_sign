# frozen_string_literal: true

require_relative "../pdf/native_signer"

module EasyCodeSign
  module Signable
    # Handler for signing PDF files using the native MIT-licensed backend.
    #
    # Signs PDFs using ISO 32000 incremental-update signatures (adbe.pkcs7.detached).
    # No HexaPDF (AGPL) dependency — signing is done via NativeSigner + CmsBuilder.
    #
    # @example Sign a PDF with a hardware-token provider
    #   pdf = PdfFile.new("document.pdf",
    #                     output_path:    "document_signed.pdf",
    #                     signature_reason:   "Approval",
    #                     signature_location: "Athens")
    #   pdf.apply_signature(->(hash) { provider.sign_bytes(hash) }, [cert])
    #
    class PdfFile < Base
      SUPPORTED_EXTENSIONS = %w[.pdf].freeze

      attr_reader :signature_config

      def initialize(file_path, **options)
        super
        validate_pdf!
        @signature_config = build_signature_config(options)
      end

      # Apply an ISO 32000 incremental-update signature to this PDF.
      #
      # @param signature_or_callback [String, Proc]
      #   - Proc: called with SHA256(signed_attrs_DER) → returns raw RSA signature bytes
      #   - String: pre-computed raw RSA signature bytes (used as-is)
      # @param certificate_chain [Array<OpenSSL::X509::Certificate>]
      #   First element is the signing certificate; rest are chain certs.
      # @return [String] path to the signed output file
      def apply_signature(signature_or_callback, certificate_chain, timestamp_token: nil)
        signing_certificate = certificate_chain.first

        sign_proc = if signature_or_callback.respond_to?(:call)
                      signature_or_callback
                    else
                      raw = signature_or_callback
                      ->(_hash) { raw }
                    end

        signer = Pdf::NativeSigner.new(
          pdf_path:           file_path,
          output_path:        output_path,
          certificate:        signing_certificate,
          certificate_chain:  certificate_chain[1..] || [],
          reason:             @signature_config[:reason],
          location:           @signature_config[:location],
          contact_info:       @signature_config[:contact_info],
          metadata:           @signature_config[:metadata],
          metadata_namespace: @signature_config[:metadata_namespace],
          metadata_prefix:    @signature_config[:metadata_prefix]
        )
        signer.sign { |hash| sign_proc.call(hash) }
      end

      # Extract the last signature from this PDF by scanning the raw bytes.
      # Works for any PDF signed with the native backend (adbe.pkcs7.detached).
      #
      # @return [Hash, nil] :contents (binary DER), :byte_range, :sub_filter — or nil if unsigned
      def extract_signature
        raw = File.binread(file_path)

        contents_hex = nil
        raw.scan(%r{/Contents\s*<([0-9a-fA-F]*)>}) { |m| contents_hex = m[0] }
        return nil unless contents_hex

        br_str = nil
        raw.scan(%r{/ByteRange\s*\[([^\]]+)\]}) { |m| br_str = m[0] }
        return nil unless br_str

        br_values = br_str.split.map(&:to_i)
        return nil unless br_values.size == 4

        {
          contents:   [contents_hex].pack("H*"),
          byte_range: br_values,
          sub_filter: raw[%r{/SubFilter\s*/(\S+)}, 1]
        }
      rescue StandardError
        nil
      end

      private

      def validate_pdf!
        ext = File.extname(file_path).downcase
        unless SUPPORTED_EXTENSIONS.include?(ext)
          raise InvalidPdfError, "File must be a PDF: #{file_path}"
        end

        File.open(file_path, "rb") do |f|
          header = f.read(8)
          unless header&.start_with?("%PDF-")
            raise InvalidPdfError, "Invalid PDF file (bad header): #{file_path}"
          end
        end
      end

      def build_signature_config(opts)
        {
          visible:            opts.fetch(:visible_signature, false),
          page:               opts.fetch(:signature_page, 1),
          position:           opts.fetch(:signature_position, :bottom_right),
          rect:               opts[:signature_rect],
          reason:             opts[:signature_reason],
          location:           opts[:signature_location],
          contact_info:       opts[:signature_contact],
          metadata:           opts.fetch(:signature_metadata, {}),
          metadata_namespace: opts[:signature_metadata_namespace],
          metadata_prefix:    opts[:signature_metadata_prefix]
        }
      end
    end
  end
end
