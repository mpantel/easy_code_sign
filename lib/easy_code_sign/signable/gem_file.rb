# frozen_string_literal: true

require "rubygems/package"
require "openssl"
require "tempfile"
require "fileutils"

module EasyCodeSign
  module Signable
    # Handler for signing Ruby gem files (.gem)
    #
    # Gem signing follows the RubyGems signing format:
    # - Creates PKCS#7 detached signatures for data.tar.gz, metadata.gz, checksums.yaml.gz
    # - Signature files are stored as .sig files in the gem archive
    #
    # @example
    #   gem_file = EasyCodeSign::Signable::GemFile.new("my_gem-1.0.0.gem")
    #   gem_file.prepare_for_signing
    #   signature = provider.sign(gem_file.content_to_sign, algorithm: :sha256_rsa)
    #   gem_file.apply_signature(signature, [cert])
    #
    class GemFile < Base
      # Files within the gem that get signed
      SIGNABLE_FILES = %w[data.tar.gz metadata.gz checksums.yaml.gz].freeze

      def initialize(file_path, **options)
        super
        validate_gem_format!
        @contents = {}
        @signatures = {}
      end

      def prepare_for_signing
        extract_gem_contents
      end

      # Returns concatenated hashes of all signable files
      # This is what gets signed by the hardware token
      def content_to_sign
        prepare_for_signing if @contents.empty?

        # Create a digest of all signable content
        combined = SIGNABLE_FILES.filter_map do |name|
          content = @contents[name]
          next unless content

          "#{name}:#{compute_hash(content).unpack1('H*')}"
        end.join("\n")

        compute_hash(combined)
      end

      def apply_signature(signature, certificate_chain, timestamp_token: nil)
        prepare_for_signing if @contents.empty?

        # Build PKCS#7 signature structure for each file
        SIGNABLE_FILES.each do |name|
          content = @contents[name]
          next unless content

          pkcs7_sig = build_pkcs7_signature(content, signature, certificate_chain, timestamp_token)
          @signatures["#{name}.sig"] = pkcs7_sig.to_der
        end

        write_signed_gem
      end

      def extract_signature
        sigs = {}

        File.open(file_path, "rb") do |io|
          Gem::Package::TarReader.new(io) do |tar|
            tar.each do |entry|
              next unless entry.full_name.end_with?(".sig")

              sigs[entry.full_name] = entry.read
            end
          end
        end

        sigs.empty? ? nil : sigs
      rescue StandardError
        nil
      end

      # Get the gem specification
      # @return [Gem::Specification, nil]
      def spec
        @spec ||= extract_gemspec
      end

      private

      def validate_gem_format!
        unless file_path.end_with?(".gem")
          raise InvalidFileError, "File must have .gem extension: #{file_path}"
        end

        # Verify it's a valid tar archive
        File.open(file_path, "rb") do |io|
          Gem::Package::TarReader.new(io) do |tar|
            tar.first # Just check we can read it
          end
        end
      rescue Gem::Package::TarInvalidError => e
        raise InvalidFileError, "Invalid gem file: #{e.message}"
      end

      def extract_gem_contents
        @contents = {}

        File.open(file_path, "rb") do |io|
          Gem::Package::TarReader.new(io) do |tar|
            tar.each do |entry|
              if SIGNABLE_FILES.include?(entry.full_name)
                @contents[entry.full_name] = entry.read
              end
            end
          end
        end

        if @contents.empty?
          raise InvalidFileError, "Gem file contains no signable content"
        end

        @contents
      end

      def extract_gemspec
        File.open(file_path, "rb") do |io|
          Gem::Package::TarReader.new(io) do |tar|
            tar.each do |entry|
              if entry.full_name == "metadata.gz"
                require "zlib"
                yaml = Zlib::GzipReader.new(StringIO.new(entry.read)).read
                return Gem::Specification.from_yaml(yaml)
              end
            end
          end
        end
        nil
      rescue StandardError
        nil
      end

      def build_pkcs7_signature(content, raw_signature, certificate_chain, timestamp_token)
        # Create PKCS#7 signed data structure
        signing_cert = certificate_chain.first

        pkcs7 = OpenSSL::PKCS7.new
        pkcs7.type = "signed"

        # Add certificates to the signature
        certificate_chain.each do |cert|
          pkcs7.add_certificate(cert)
        end

        # Create signer info
        # Note: We're using a pre-computed signature from the hardware token
        # This creates a compatible PKCS#7 structure
        signer_info = OpenSSL::PKCS7::SignerInfo.new(
          signing_cert,
          nil, # We don't have the private key - signature was made by HSM
          digest_class.name.split("::").last
        )

        # The actual signature from the HSM needs to be embedded
        # This is a simplified version - full implementation would need
        # to properly construct the SignerInfo with the external signature

        pkcs7.add_signer(signer_info)
        pkcs7.add_data(content)

        # Add timestamp if provided
        if timestamp_token
          # Timestamp would be added as an unsigned attribute
          # Implementation depends on how we receive the timestamp
        end

        pkcs7
      end

      def write_signed_gem
        output = output_path
        temp_file = Tempfile.new(["signed_gem", ".gem"])

        begin
          # Write new gem with signatures
          File.open(temp_file.path, "wb") do |out_io|
            Gem::Package::TarWriter.new(out_io) do |tar|
              # First, copy all original entries
              File.open(file_path, "rb") do |in_io|
                Gem::Package::TarReader.new(in_io) do |reader|
                  reader.each do |entry|
                    # Skip existing signatures if re-signing
                    next if entry.full_name.end_with?(".sig")

                    tar.add_file_simple(entry.full_name, entry.header.mode, entry.size) do |io|
                      io.write(entry.read)
                    end
                  end
                end
              end

              # Add signature files
              @signatures.each do |name, sig_data|
                tar.add_file_simple(name, 0o444, sig_data.bytesize) do |io|
                  io.write(sig_data)
                end
              end
            end
          end

          # Move temp file to output location
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
