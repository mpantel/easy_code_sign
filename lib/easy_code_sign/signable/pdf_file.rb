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

      # Phase 1 of deferred signing: prepare PDF with placeholder signature,
      # capture the digest that needs to be signed externally.
      #
      # HexaPDF builds the CMS signed attributes internally (since certificate IS set).
      # The external_signing lambda receives (digest_algorithm, hash) where hash is the
      # digest of the DER-encoded signed attributes — exactly what the external signer
      # must sign. We capture it and return "" to leave the /Contents zero-filled.
      #
      # @param certificate [OpenSSL::X509::Certificate] signing certificate
      # @param certificate_chain [Array<OpenSSL::X509::Certificate>] full chain
      # @param digest_algorithm [String] "sha256", "sha384", or "sha512"
      # @param timestamp_size [Integer] extra bytes to reserve for timestamp (0 if none)
      # @return [DeferredSigningRequest]
      def prepare_deferred(certificate, certificate_chain, digest_algorithm: "sha256", timestamp_size: 0)
        captured_digest = nil
        captured_algorithm = nil
        signing_time = Time.now

        external_signing = lambda do |algo, hash|
          captured_algorithm = algo
          captured_digest = hash
          "" # Empty string signals async to HexaPDF
        end

        estimated_size = calculate_deferred_signature_size(certificate_chain, timestamp_size)

        document = HexaPDF::Document.open(file_path)
        handler = document.signatures.signing_handler(
          certificate: certificate,
          certificate_chain: certificate_chain[1..] || [],
          external_signing: external_signing,
          digest_algorithm: digest_algorithm,
          signature_size: estimated_size,
          signing_time: signing_time,
          reason: @signature_config[:reason],
          location: @signature_config[:location],
          contact_info: @signature_config[:contact_info]
        )

        prepared_path = deferred_output_path
        document.signatures.add(prepared_path, handler)

        # Read back the ByteRange from the prepared PDF
        byte_range = read_byte_range(prepared_path)

        # Compute pre-hash signed attributes DER for WebCrypto compatibility
        signed_attrs_der = compute_signed_attributes_data(
          prepared_path, byte_range, certificate, certificate_chain,
          digest_algorithm, signing_time
        )

        DeferredSigningRequest.new(
          digest: captured_digest,
          digest_algorithm: captured_algorithm,
          prepared_pdf_path: prepared_path,
          byte_range: byte_range,
          certificate: certificate,
          certificate_chain: certificate_chain,
          estimated_size: estimated_size,
          signing_time: signing_time,
          signed_attributes_data: signed_attrs_der
        )
      rescue HexaPDF::Error => e
        raise DeferredSigningError, "Failed to prepare PDF for deferred signing: #{e.message}"
      end

      # Phase 2 of deferred signing: rebuild CMS with the real signature and embed it.
      #
      # Re-reads the ByteRange content from the prepared PDF, invokes SignedDataCreator
      # with the same parameters as Phase 1 (including signing_time for determinism),
      # and the block returns the actual raw signature. The resulting CMS DER is embedded
      # into the prepared PDF via Signing.embed_signature.
      #
      # @param deferred_request [DeferredSigningRequest] from Phase 1
      # @param raw_signature [String] raw signature bytes from external signer
      # @return [String] path to the finalized signed PDF
      def finalize_deferred(deferred_request, raw_signature)
        prepared_path = deferred_request.prepared_pdf_path
        unless File.exist?(prepared_path)
          raise DeferredSigningError, "Prepared PDF not found: #{prepared_path}"
        end

        byte_range = deferred_request.byte_range

        # Read ByteRange content from the prepared PDF
        data = File.open(prepared_path, "rb") do |f|
          f.pos = byte_range[0]
          content = f.read(byte_range[1])
          f.pos = byte_range[2]
          content << f.read(byte_range[3])
        end

        # Rebuild the CMS structure with the actual signature
        signing_block = lambda do |_digest_algorithm, _hash|
          raw_signature
        end

        cms = HexaPDF::DigitalSignature::Signing::SignedDataCreator.create(
          data,
          type: :cms,
          certificate: deferred_request.certificate,
          digest_algorithm: deferred_request.digest_algorithm.to_s,
          signing_time: deferred_request.signing_time,
          certificates: deferred_request.certificate_chain[1..] || [],
          &signing_block
        )

        cms_der = cms.to_der

        # Embed the real signature into the prepared PDF
        File.open(prepared_path, "rb+") do |io|
          HexaPDF::DigitalSignature::Signing.embed_signature(io, cms_der)
        end

        prepared_path
      rescue HexaPDF::Error => e
        raise DeferredSigningError, "Failed to finalize deferred signature: #{e.message}"
      end

      # Extract existing signature from PDF
      # @return [Hash, nil] signature data or nil if unsigned
      def extract_signature
        doc = HexaPDF::Document.open(file_path)

        signatures = doc.signatures.each.to_a
        return nil if signatures.empty?

        # HexaPDF's signatures.each yields the Sig dictionary directly
        sig_dict = signatures.last

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

      def calculate_deferred_signature_size(certificate_chain, timestamp_size)
        base_size = 8192
        cert_size = certificate_chain.sum { |c| c.to_der.bytesize }
        base_size + cert_size + timestamp_size
      end

      def deferred_output_path
        dir = File.dirname(file_path)
        base = File.basename(file_path, File.extname(file_path))
        File.join(dir, "#{base}_prepared.pdf")
      end

      def read_byte_range(pdf_path)
        doc = HexaPDF::Document.open(pdf_path)
        sig = doc.signatures.each.to_a.last
        sig_dict = sig.is_a?(Hash) ? sig : sig
        sig_dict[:ByteRange]&.value
      end

      # Reconstruct the DER-encoded signed attributes from the prepared PDF.
      # This is the pre-hash data that WebCrypto can hash-and-sign in one step.
      # Invariant: SHA256(result) == captured_digest
      def compute_signed_attributes_data(prepared_path, byte_range, certificate, certificate_chain,
                                         digest_algorithm, signing_time)
        # Read ByteRange content (same as finalize_deferred does)
        data = File.open(prepared_path, "rb") do |f|
          f.pos = byte_range[0]
          content = f.read(byte_range[1])
          f.pos = byte_range[2]
          content << f.read(byte_range[3])
        end

        # Build a SignedDataCreator with the same params used in Phase 1
        creator = HexaPDF::DigitalSignature::Signing::SignedDataCreator.new
        creator.certificate = certificate
        creator.digest_algorithm = digest_algorithm.to_s
        creator.signing_time = signing_time
        creator.certificates = certificate_chain[1..] || []

        # Access the private method to get the ASN.1 signed attributes SET
        signed_attrs = creator.send(:create_signed_attrs, data, signing_time: true)

        # DER-encode the SET (mirrors line 113 of signed_data_creator.rb)
        OpenSSL::ASN1::Set.new(signed_attrs.value).to_der
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
