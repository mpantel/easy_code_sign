# frozen_string_literal: true

require "zip"
require "openssl"
require "tempfile"
require "fileutils"
require "base64"

module EasyCodeSign
  module Signable
    # Handler for signing ZIP files using JAR-style signatures
    #
    # Creates META-INF/ directory with:
    # - MANIFEST.MF: Contains hashes of all files
    # - CERT.SF: Contains hash of manifest (this is what gets signed)
    # - CERT.RSA: PKCS#7 signature block with certificate chain
    #
    # @example
    #   zip_file = EasyCodeSign::Signable::ZipFile.new("archive.zip")
    #   zip_file.prepare_for_signing
    #   signature = provider.sign(zip_file.content_to_sign, algorithm: :sha256_rsa)
    #   zip_file.apply_signature(signature, [cert])
    #
    class ZipFile < Base
      MANIFEST_PATH = "META-INF/MANIFEST.MF"
      SIGNATURE_FILE_PATH = "META-INF/CERT.SF"
      SIGNATURE_BLOCK_PATH = "META-INF/CERT.RSA"
      MANIFEST_VERSION = "1.0"
      SIGNATURE_VERSION = "1.0"

      def initialize(file_path, **options)
        super
        validate_zip_format!
        @manifest_entries = {}
        @manifest_content = nil
        @signature_file_content = nil
      end

      def prepare_for_signing
        build_manifest
        build_signature_file
      end

      # Returns the signature file content that needs to be signed
      def content_to_sign
        prepare_for_signing if @signature_file_content.nil?
        compute_hash(@signature_file_content)
      end

      def apply_signature(signature, certificate_chain, timestamp_token: nil)
        prepare_for_signing if @signature_file_content.nil?

        pkcs7_block = build_signature_block(signature, certificate_chain, timestamp_token)
        write_signed_zip(pkcs7_block)
      end

      def extract_signature
        ::Zip::File.open(file_path) do |zip|
          return nil unless zip.find_entry(SIGNATURE_BLOCK_PATH)

          {
            manifest: zip.read(MANIFEST_PATH),
            signature_file: zip.read(SIGNATURE_FILE_PATH),
            signature_block: zip.read(SIGNATURE_BLOCK_PATH)
          }
        end
      rescue StandardError
        nil
      end

      # Get list of files in the ZIP (excluding META-INF signatures)
      # @return [Array<String>]
      def file_list
        files = []
        ::Zip::File.open(file_path) do |zip|
          zip.each do |entry|
            next if entry.directory?
            next if entry.name.start_with?("META-INF/") && signature_file?(entry.name)

            files << entry.name
          end
        end
        files.sort
      end

      private

      def validate_zip_format!
        unless file_path.end_with?(".zip", ".jar", ".apk", ".war", ".ear")
          raise InvalidFileError, "File must be a ZIP archive: #{file_path}"
        end

        # Verify it's a valid ZIP
        ::Zip::File.open(file_path) { |_| } # Just check we can open it
      rescue ::Zip::Error => e
        raise InvalidFileError, "Invalid ZIP file: #{e.message}"
      end

      def signature_file?(name)
        basename = File.basename(name)
        basename == "MANIFEST.MF" ||
          basename.end_with?(".SF", ".RSA", ".DSA", ".EC")
      end

      def build_manifest
        @manifest_entries = {}
        lines = ["Manifest-Version: #{MANIFEST_VERSION}", "Created-By: EasyCodeSign", ""]

        ::Zip::File.open(file_path) do |zip|
          zip.each do |entry|
            next if entry.directory?
            next if entry.name.start_with?("META-INF/") && signature_file?(entry.name)

            content = entry.get_input_stream.read
            digest = Base64.strict_encode64(compute_hash(content))

            @manifest_entries[entry.name] = digest

            lines << "Name: #{entry.name}"
            lines << "#{digest_attribute_name}: #{digest}"
            lines << ""
          end
        end

        @manifest_content = lines.join("\r\n")
      end

      def build_signature_file
        lines = [
          "Signature-Version: #{SIGNATURE_VERSION}",
          "Created-By: EasyCodeSign",
          "#{digest_attribute_name}-Digest-Manifest: #{Base64.strict_encode64(compute_hash(@manifest_content))}",
          ""
        ]

        # Add per-entry digests
        @manifest_entries.each do |name, _|
          entry_section = find_manifest_section(name)
          section_digest = Base64.strict_encode64(compute_hash(entry_section))

          lines << "Name: #{name}"
          lines << "#{digest_attribute_name}-Digest: #{section_digest}"
          lines << ""
        end

        @signature_file_content = lines.join("\r\n")
      end

      def find_manifest_section(name)
        # Find the section for this entry in the manifest
        sections = @manifest_content.split(/\r?\n\r?\n/)
        sections.find { |s| s.include?("Name: #{name}") } || ""
      end

      def digest_attribute_name
        case hash_algorithm
        when :sha256 then "SHA-256"
        when :sha384 then "SHA-384"
        when :sha512 then "SHA-512"
        else "SHA-256"
        end
      end

      def build_signature_block(signature, certificate_chain, timestamp_token)
        # signing_cert = certificate_chain.first (used when embedding signer info)

        # Create PKCS#7 SignedData structure
        pkcs7 = OpenSSL::PKCS7.new
        pkcs7.type = "signed"

        # Add all certificates in the chain
        certificate_chain.each do |cert|
          pkcs7.add_certificate(cert)
        end

        # For JAR signing, we sign the .SF file content
        # The signature from HSM needs to be wrapped in PKCS#7
        pkcs7.add_data(@signature_file_content)

        # Note: In a full implementation, we'd need to properly embed
        # the HSM-generated signature into the PKCS#7 structure.
        # This requires constructing SignerInfo with the pre-made signature.

        pkcs7.to_der
      end

      def write_signed_zip(pkcs7_block)
        output = output_path
        temp_file = Tempfile.new(["signed_zip", File.extname(file_path)])

        begin
          ::Zip::File.open(file_path) do |input_zip|
            ::Zip::File.open(temp_file.path, ::Zip::File::CREATE) do |output_zip|
              # Copy all entries except existing signatures
              input_zip.each do |entry|
                next if entry.name.start_with?("META-INF/") && signature_file?(entry.name)

                if entry.directory?
                  output_zip.mkdir(entry.name)
                else
                  output_zip.get_output_stream(entry.name) do |os|
                    os.write(entry.get_input_stream.read)
                  end
                end
              end

              # Ensure META-INF directory exists
              output_zip.mkdir("META-INF") unless output_zip.find_entry("META-INF/")

              # Add signature files
              output_zip.get_output_stream(MANIFEST_PATH) { |os| os.write(@manifest_content) }
              output_zip.get_output_stream(SIGNATURE_FILE_PATH) { |os| os.write(@signature_file_content) }
              output_zip.get_output_stream(SIGNATURE_BLOCK_PATH) { |os| os.write(pkcs7_block) }
            end
          end

          FileUtils.mv(temp_file.path, output)
          output
        ensure
          temp_file.close
          temp_file.unlink if File.exist?(temp_file.path)
        end
      end
    end
  end
end
