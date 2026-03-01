# frozen_string_literal: true

require "openssl"
require "pdf-reader"
require_relative "cms_builder"

module EasyCodeSign
  module Pdf
    # Signs a PDF using a pure-OpenSSL/MIT approach (no HexaPDF).
    #
    # Implements ISO 32000 incremental-update signature:
    #   1. Appends new objects (sig dict, sig field, updated catalog) to the original PDF.
    #   2. Appends a cross-reference table and trailer (/Prev chains to original).
    #   3. Writes a fixed-size /Contents placeholder (zeros).
    #   4. Computes ByteRange = [0, placeholder_start, placeholder_end, rest_of_file].
    #   5. Patches ByteRange into the file (fixed-width replacement).
    #   6. Signs the ByteRange content via CmsBuilder + the caller's sign_bytes block.
    #   7. Embeds the CMS DER hex into the /Contents slot.
    #
    class NativeSigner
      # Reserved binary bytes for CMS DER. RSA-2048 + self-signed cert < 4 KiB.
      # 8 KiB gives headroom for small certificate chains.
      SIGNATURE_PLACEHOLDER_SIZE = 8192

      # Fixed-width ByteRange placeholder written before the real values are known.
      # Four 10-digit zero-padded integers + brackets = always 44 chars.
      BR_PLACEHOLDER = "[0000000000 0000000000 0000000000 0000000000]"

      def initialize(pdf_path:, output_path:, certificate:, certificate_chain: [],
                     reason: nil, location: nil, contact_info: nil, signing_time: nil)
        @pdf_path          = pdf_path
        @output_path       = output_path
        @certificate       = certificate
        @certificate_chain = certificate_chain
        @reason            = reason
        @location          = location
        @contact_info      = contact_info
        @signing_time      = signing_time || Time.now
      end

      # Produce a signed PDF.
      # @yield [hash] binary String — SHA256(signed_attrs_DER), per HexaPDF external_signing convention
      # @yieldreturn [String] raw RSA-PKCS#1-v1.5 signature bytes
      # @return [String] @output_path
      def sign(&sign_bytes)
        raise ArgumentError, "sign_bytes block required" unless sign_bytes

        original = File.binread(@pdf_path)
        reader   = PDF::Reader.new(StringIO.new(original))
        trailer  = reader.objects.trailer

        orig_startxref  = find_startxref(original)
        orig_size       = trailer[:Size].to_i
        root_ref        = trailer[:Root]

        # New object numbers
        sig_obj_num   = orig_size
        field_obj_num = orig_size + 1

        # The incremental update begins after a "\n" separator
        base = original.bytesize + 1  # +1 for the separator newline

        # Build object bodies and track their absolute offsets in the combined file
        sig_body, contents_body_rel = build_sig_body(sig_obj_num)
        sig_offset        = base
        contents_abs      = sig_offset + contents_body_rel

        field_body   = build_field_body(field_obj_num, sig_obj_num)
        field_offset = sig_offset + sig_body.bytesize

        catalog_obj_num = root_ref.id
        catalog_gen     = root_ref.gen
        catalog_body    = build_catalog_body(catalog_obj_num, catalog_gen,
                                             field_obj_num, root_ref, reader)
        catalog_offset  = field_offset + field_body.bytesize

        xref_offset = catalog_offset + catalog_body.bytesize

        xref_str = build_xref(
          sig_obj_num    => sig_offset,
          field_obj_num  => field_offset,
          catalog_obj_num => catalog_offset
        )

        new_size    = [sig_obj_num, field_obj_num, catalog_obj_num].max + 1
        trailer_str = "trailer\n" \
          "<</Size #{new_size}" \
          " /Root #{ref(catalog_obj_num, catalog_gen)}" \
          " /Prev #{orig_startxref}>>\n" \
          "startxref\n#{xref_offset}\n%%EOF\n"

        combined = original +
                   "\n" +
                   sig_body + field_body + catalog_body +
                   xref_str + trailer_str

        File.binwrite(@output_path, combined)

        # contents_abs is the absolute offset of '<' in /Contents <hex> in the combined file
        contents_total = SIGNATURE_PLACEHOLDER_SIZE * 2 + 2  # '<' + hex_zeros + '>'
        byte_range = [
          0,
          contents_abs,
          contents_abs + contents_total,
          combined.bytesize - (contents_abs + contents_total)
        ]

        patch_byte_range(byte_range)

        data = read_byte_ranges(byte_range)

        builder = CmsBuilder.new(
          certificate:       @certificate,
          certificate_chain: @certificate_chain,
          signing_time:      @signing_time
        )
        cms_der = builder.build(data, &sign_bytes)

        embed_signature(contents_abs, cms_der)

        @output_path
      end

      private

      # ------------------------------------------------------------------ #
      # Object body builders                                                 #
      # ------------------------------------------------------------------ #

      # Returns [body_string, byte_offset_of_'<'_within_body]
      def build_sig_body(obj_num)
        hex_zeros = "0" * (SIGNATURE_PLACEHOLDER_SIZE * 2)

        header = "#{obj_num} 0 obj\n" \
          "<</Type /Sig\n" \
          "/Filter /Adobe.PPKLite\n" \
          "/SubFilter /adbe.pkcs7.detached\n" \
          "/ByteRange #{BR_PLACEHOLDER}\n" \
          "/Contents <"

        footer = ">"
        footer += "\n/Reason #{pdf_str(@reason)}"    if @reason
        footer += "\n/Location #{pdf_str(@location)}" if @location
        footer += "\n/ContactInfo #{pdf_str(@contact_info)}" if @contact_info
        footer += "\n>>\nendobj\n"

        body = header + hex_zeros + footer
        [body, header.bytesize - 1]  # -1 → points at '<'
      end

      def build_field_body(obj_num, sig_obj_num)
        "#{obj_num} 0 obj\n" \
          "<</Type /Annot\n" \
          "/Subtype /Widget\n" \
          "/FT /Sig\n" \
          "/V #{ref(sig_obj_num, 0)}\n" \
          "/Rect [0 0 0 0]\n" \
          "/F 4\n" \
          "/T (Signature1)\n" \
          ">>\nendobj\n"
      end

      def build_catalog_body(obj_num, gen, field_obj_num, root_ref, reader)
        catalog = reader.objects[root_ref] || {}

        parts = ["/Type /Catalog"]

        if catalog[:Pages]
          pr = catalog[:Pages]
          parts << "/Pages #{ref(pr.id, pr.gen)}"
        end

        # Preserve common catalog entries
        %i[ViewerPreferences PageLayout PageMode Names Outlines MarkInfo Lang].each do |key|
          val = catalog[key]
          next unless val
          parts << "/#{key} #{pdf_val(val)}"
        end

        parts << "/AcroForm <</Fields [#{ref(field_obj_num, 0)}] /SigFlags 3>>"

        "#{obj_num} #{gen} obj\n<<#{parts.join("\n")}>>\nendobj\n"
      end

      # ------------------------------------------------------------------ #
      # Cross-reference table                                                #
      # ------------------------------------------------------------------ #

      # Writes separate 1-entry subsections — always valid PDF
      def build_xref(entries)
        out = +"xref\n"
        entries.sort_by { |num, _| num }.each do |num, offset|
          out << "#{num} 1\n"
          out << "#{offset.to_s.rjust(10, "0")} 00000 n \n"
        end
        out
      end

      # ------------------------------------------------------------------ #
      # ByteRange + signature embedding                                      #
      # ------------------------------------------------------------------ #

      def patch_byte_range(byte_range)
        content = File.binread(@output_path)
        br_str  = "[#{byte_range.map { |v| v.to_s.rjust(10, "0") }.join(" ")}]"
        raise "ByteRange value too wide" if br_str.bytesize > BR_PLACEHOLDER.bytesize

        idx = content.index("/ByteRange #{BR_PLACEHOLDER}")
        raise InvalidPdfError, "ByteRange placeholder not found" unless idx

        start = idx + "/ByteRange ".bytesize
        content[start, BR_PLACEHOLDER.bytesize] = br_str.ljust(BR_PLACEHOLDER.bytesize)
        File.binwrite(@output_path, content)
      end

      def read_byte_ranges(byte_range)
        File.open(@output_path, "rb") do |f|
          f.pos = byte_range[0]
          chunk = f.read(byte_range[1])
          f.pos = byte_range[2]
          chunk << f.read(byte_range[3])
        end
      end

      def embed_signature(contents_abs, cms_der)
        hex = cms_der.unpack1("H*")
        if hex.bytesize > SIGNATURE_PLACEHOLDER_SIZE * 2
          raise PdfSignatureError, "CMS DER (#{hex.bytesize / 2} bytes) exceeds reserved " \
                                   "#{SIGNATURE_PLACEHOLDER_SIZE} bytes"
        end
        padded = hex.ljust(SIGNATURE_PLACEHOLDER_SIZE * 2, "0")
        File.open(@output_path, "rb+") do |f|
          f.pos = contents_abs          # '<' of /Contents <hex>
          f.write("<#{padded}>")
        end
      end

      # ------------------------------------------------------------------ #
      # Helpers                                                              #
      # ------------------------------------------------------------------ #

      def find_startxref(bytes)
        tail = bytes.byteslice([bytes.bytesize - 1024, 0].max, 1024) || bytes
        m    = tail.match(/startxref\s+(\d+)\s*%%EOF/)
        raise InvalidPdfError, "Cannot locate startxref in PDF" unless m
        m[1].to_i
      end

      def ref(id, gen)
        "#{id} #{gen} R"
      end

      def pdf_str(str)
        "(#{str.gsub("\\", "\\\\\\\\").gsub("(", "\\(").gsub(")", "\\)")})"
      end

      def pdf_val(val)
        case val
        when PDF::Reader::Reference then ref(val.id, val.gen)
        when Symbol                 then "/#{val}"
        when String                 then pdf_str(val)
        when TrueClass              then "true"
        when FalseClass             then "false"
        when NilClass               then "null"
        when Array                  then "[#{val.map { |v| pdf_val(v) }.join(" ")}]"
        when Hash
          inner = val.map { |k, v| "/#{k} #{pdf_val(v)}" }.join(" ")
          "<<#{inner}>>"
        else
          val.to_s
        end
      end
    end
  end
end
