# frozen_string_literal: true

require "hexapdf"

module EasyCodeSign
  module Signable
    # Handler for signing PDF files
    #
    # PDF signatures use a ByteRange approach where specific byte ranges are signed,
    # excluding the signature field itself. This allows incremental updates.
    #
    # @example Sign a PDF
    #   pdf = PdfFile.new("document.pdf")
    #   pdf.prepare_for_signing
    #   content = pdf.content_to_sign
    #   # ... sign content with HSM ...
    #   pdf.apply_signature(signature, certificate_chain)
    #
    class PdfFile < Base
      SUPPORTED_EXTENSIONS = %w[.pdf].freeze

      # Signature appearance configuration
      attr_reader :signature_config

      def initialize(file_path, **options)
        super
        validate_pdf!
        @signature_config = build_signature_config(options)
        @document = nil
        @signature_field = nil
        @prepared_data = nil
      end

      # Prepare PDF for signing by creating signature field and calculating ByteRange
      # @return [void]
      def prepare_for_signing
        @document = HexaPDF::Document.open(file_path)

        # Create signature field
        @signature_field = create_signature_field

        # Set up the signing handler that will be called by HexaPDF
        @prepared_data = {
          document: @document,
          signature_field: @signature_field
        }
      end

      # Get content to sign (hash of ByteRange content)
      # HexaPDF calculates this during the signing process
      # @return [String] placeholder - actual content determined during apply_signature
      def content_to_sign
        prepare_for_signing if @prepared_data.nil?

        # For PDF signing, the actual content to sign is determined by ByteRange
        # during the signature embedding process. We return a placeholder here
        # and handle the actual signing in apply_signature via a custom handler.
        #
        # The real signing happens through ExternalSigningHandler which receives
        # the ByteRange content from HexaPDF.
        "PDF_SIGNING_PLACEHOLDER"
      end

      # Apply signature to PDF
      # @param signature_or_callback [String, Proc] raw signature bytes or signing callback
      # @param certificate_chain [Array<OpenSSL::X509::Certificate>] certificate chain
      # @param timestamp_token [Timestamp::Response, Proc, nil] optional timestamp or lazy accessor
      # @return [String] path to signed PDF
      def apply_signature(signature_or_callback, certificate_chain, timestamp_token: nil)
        prepare_for_signing if @prepared_data.nil?

        signing_certificate = certificate_chain.first

        # Create the signing handler with external signing support
        signing_key = if signature_or_callback.respond_to?(:call)
                        # Callback-based signing (for HSM)
                        ExternalSigningCallback.new(signature_or_callback)
                      else
                        # Pre-computed signature
                        ExternalSigningProxy.new(signature_or_callback, signing_certificate, certificate_chain)
                      end

        # Estimate signature size for placeholder
        estimated_size = calculate_signature_size(certificate_chain, timestamp_token)

        # Configure signature handler
        handler = @document.signatures.handler_for_signing(
          @signature_field,
          certificate: signing_certificate,
          key: signing_key,
          certificate_chain: certificate_chain[1..] || [],
          reason: @signature_config[:reason],
          location: @signature_config[:location],
          contact_info: @signature_config[:contact_info],
          signature_size: estimated_size
        )

        # Build visible appearance if configured
        if @signature_config[:visible]
          build_visible_appearance(handler, signing_certificate)
        end

        # Write signed PDF
        out_path = output_path
        @document.signatures.sign(@signature_field, handler, write_options: { output: out_path })

        out_path
      end

      # Extract existing signature from PDF
      # @return [Hash, nil] signature data or nil if unsigned
      def extract_signature
        doc = HexaPDF::Document.open(file_path)

        signatures = doc.signatures.each.to_a
        return nil if signatures.empty?

        # Return the last (most recent) signature
        sig = signatures.last
        sig_dict = sig[:V]

        return nil unless sig_dict

        {
          contents: sig_dict[:Contents],
          byte_range: sig_dict[:ByteRange]&.value,
          sub_filter: sig_dict[:SubFilter]&.to_s,
          reason: sig_dict[:Reason],
          location: sig_dict[:Location],
          contact_info: sig_dict[:ContactInfo],
          signing_time: sig_dict[:M],
          name: sig_dict[:Name]
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

        # Verify PDF header
        File.open(file_path, "rb") do |f|
          header = f.read(8)
          unless header&.start_with?("%PDF-")
            raise InvalidPdfError, "Invalid PDF file (bad header): #{file_path}"
          end
        end
      end

      def build_signature_config(opts)
        {
          visible: opts.fetch(:visible_signature, false),
          page: opts.fetch(:signature_page, 1),
          position: opts.fetch(:signature_position, :bottom_right),
          rect: opts[:signature_rect],
          reason: opts[:signature_reason],
          location: opts[:signature_location],
          contact_info: opts[:signature_contact]
        }
      end

      def create_signature_field
        page_index = [@signature_config[:page] - 1, 0].max
        page = @document.pages[page_index] || @document.pages.add

        # Create signature form field
        form = @document.acro_form(create: true)
        sig_field = form.create_signature_field("Signature1")

        # Add visible appearance if requested
        if @signature_config[:visible]
          sig_field.create_widget(page, Rect: calculate_signature_rect(page))
          # Appearance will be built during signing
        else
          # Invisible signature
          sig_field.create_widget(page, Rect: [0, 0, 0, 0])
        end

        sig_field
      end

      def calculate_signature_rect(page)
        if @signature_config[:rect]
          return @signature_config[:rect]
        end

        # Calculate position based on preset
        box = page.box(:media)
        width = 200
        height = 50
        margin = 36

        case @signature_config[:position].to_sym
        when :top_left
          [margin, box.height - margin - height, margin + width, box.height - margin]
        when :top_right
          [box.width - margin - width, box.height - margin - height, box.width - margin, box.height - margin]
        when :bottom_left
          [margin, margin, margin + width, margin + height]
        when :bottom_right
          [box.width - margin - width, margin, box.width - margin, margin + height]
        else
          [box.width - margin - width, margin, box.width - margin, margin + height]
        end
      end

      def calculate_signature_size(certificate_chain, timestamp_token)
        # Estimate PKCS#7 signature size
        # Base size + certificates + timestamp
        base_size = 8192
        cert_size = certificate_chain.sum { |c| c.to_der.bytesize }
        timestamp_size = timestamp_token ? 4096 : 0

        base_size + cert_size + timestamp_size
      end

      def build_visible_appearance(handler, certificate)
        # Get the widget annotation for the signature field
        widget = @signature_field.each_widget.first
        return unless widget

        rect = widget[:Rect].value
        width = rect[2] - rect[0]
        height = rect[3] - rect[1]

        # Create appearance form XObject
        form = @document.add({ Type: :XObject, Subtype: :Form, BBox: [0, 0, width, height] })
        canvas = form.canvas

        # Draw border
        canvas.stroke_color(0, 0, 0)
        canvas.line_width(0.5)
        canvas.rectangle(0.5, 0.5, width - 1, height - 1)
        canvas.stroke

        # Draw signature text
        canvas.font("Helvetica", size: 8)
        canvas.fill_color(0, 0, 0)

        y_pos = height - 12
        x_pos = 5

        # Signer name
        signer_name = extract_cn_from_certificate(certificate)
        canvas.text("Digitally signed by:", at: [x_pos, y_pos])
        y_pos -= 10
        canvas.text(signer_name, at: [x_pos, y_pos])
        y_pos -= 12

        # Reason
        if @signature_config[:reason]
          canvas.text("Reason: #{@signature_config[:reason]}", at: [x_pos, y_pos])
          y_pos -= 10
        end

        # Location
        if @signature_config[:location]
          canvas.text("Location: #{@signature_config[:location]}", at: [x_pos, y_pos])
          y_pos -= 10
        end

        # Date
        canvas.text("Date: #{Time.now.strftime('%Y-%m-%d %H:%M')}", at: [x_pos, y_pos])

        # Set the appearance
        widget[:AP] = { N: form }
      end

      def extract_cn_from_certificate(certificate)
        subject = certificate.subject.to_a
        cn = subject.find { |name, _, _| name == "CN" }
        cn ? cn[1] : certificate.subject.to_s
      end
    end

    # Callback-based signing for HSM integration
    # HexaPDF calls #sign with the actual data to sign (ByteRange content)
    class ExternalSigningCallback
      def initialize(signing_proc)
        @signing_proc = signing_proc
      end

      # Called by HexaPDF during signing with the ByteRange content
      def sign(data, _digest_algorithm)
        @signing_proc.call(data)
      end

      def private?
        true
      end
    end

    # Proxy object that provides pre-computed signature to HexaPDF
    # HexaPDF expects a key object that responds to #sign, but we've already
    # signed with the HSM, so we return the pre-computed signature
    class ExternalSigningProxy
      attr_reader :certificate

      def initialize(signature, certificate, certificate_chain)
        @signature = signature
        @certificate = certificate
        @certificate_chain = certificate_chain
      end

      # Called by HexaPDF's DefaultHandler during signing
      # Returns pre-computed signature from HSM
      def sign(data, digest_algorithm)
        @signature
      end

      # HexaPDF checks this for RSA keys
      def private?
        true
      end
    end
  end
end
