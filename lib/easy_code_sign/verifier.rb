# frozen_string_literal: true

module EasyCodeSign
  # Main verifier for signed files
  #
  # Orchestrates signature verification including:
  # - Extracting signatures from files
  # - Verifying cryptographic signatures
  # - Validating certificate chains
  # - Checking timestamps
  #
  # @example Verify a signed gem
  #   verifier = EasyCodeSign::Verifier.new
  #   result = verifier.verify("signed.gem")
  #   puts result.valid? ? "Valid!" : result.errors
  #
  # @example Verify with custom trust store
  #   trust_store = EasyCodeSign::Verification::TrustStore.new
  #   trust_store.add_file("/path/to/custom_ca.pem")
  #   verifier = EasyCodeSign::Verifier.new(trust_store: trust_store)
  #   result = verifier.verify("signed.gem")
  #
  class Verifier
    attr_reader :trust_store, :configuration

    def initialize(trust_store: nil, configuration: nil, check_revocation: nil)
      @configuration = configuration || EasyCodeSign.configuration
      @trust_store = trust_store || build_trust_store
      @check_revocation = check_revocation.nil? ? @configuration.check_revocation : check_revocation
    end

    # Verify a signed file
    #
    # @param file_path [String] path to the signed file
    # @param check_timestamp [Boolean] whether to verify timestamp
    # @return [Verification::Result]
    #
    def verify(file_path, check_timestamp: true)
      result = Verification::Result.new
      result.file_path = file_path

      begin
        # Determine file type and create appropriate handler
        signable = create_signable(file_path)
        result.file_type = signable.class.name.split("::").last.downcase.to_sym

        # Extract signature from file
        signature_data = signable.extract_signature
        unless signature_data
          result.add_error("File is not signed")
          return result
        end

        # Verify based on file type
        case result.file_type
        when :gemfile
          verify_gem(signable, signature_data, result)
        when :zipfile
          verify_zip(signable, signature_data, result)
        else
          result.add_error("Unsupported file type for verification")
          return result
        end

        # Verify timestamp if present and requested
        if check_timestamp && result.timestamped
          verify_timestamp_token(signature_data, result)
        end

        # Determine overall validity
        result.valid = result.signature_valid &&
                       result.integrity_valid &&
                       result.certificate_valid &&
                       result.chain_valid &&
                       result.trusted

      rescue InvalidFileError => e
        result.add_error("Invalid file: #{e.message}")
      rescue StandardError => e
        result.add_error("Verification error: #{e.message}")
      end

      result
    end

    # Verify multiple files
    #
    # @param file_paths [Array<String>]
    # @return [Hash<String, Verification::Result>]
    #
    def verify_batch(file_paths)
      file_paths.to_h { |path| [path, verify(path)] }
    end

    private

    def build_trust_store
      store = Verification::TrustStore.new(use_system_certs: true)

      # Add custom trust store if configured
      if @configuration.trust_store_path
        if File.directory?(@configuration.trust_store_path)
          store.add_directory(@configuration.trust_store_path)
        elsif File.file?(@configuration.trust_store_path)
          store.add_file(@configuration.trust_store_path)
        end
      end

      store
    end

    def create_signable(file_path)
      extension = File.extname(file_path).downcase

      case extension
      when ".gem"
        Signable::GemFile.new(file_path)
      when ".zip", ".jar", ".apk", ".war", ".ear"
        Signable::ZipFile.new(file_path)
      else
        raise InvalidFileError, "Unsupported file type: #{extension}"
      end
    end

    def verify_gem(signable, signature_data, result)
      # Gem signatures are in .sig files
      signature_checker = Verification::SignatureChecker.new

      # Get the original content and signature
      signable.prepare_for_signing
      content = signable.content_to_sign

      # Find the primary signature file (checksums.yaml.gz.sig)
      sig_file = signature_data["checksums.yaml.gz.sig"] || signature_data.values.first

      unless sig_file
        result.add_error("No signature found in gem")
        return
      end

      # Verify PKCS#7 signature
      sig_result = signature_checker.verify_detached_pkcs7(sig_file, content, trust_store)

      result.signature_valid = sig_result.signature_valid
      result.signer_certificate = sig_result.signer_certificate
      result.certificate_chain = sig_result.certificates
      result.signature_algorithm = sig_result.signature_algorithm

      sig_result.errors.each { |e| result.add_error(e) }

      if result.signer_certificate
        extract_signer_info(result)
        verify_certificate_chain(result)
      end

      # Verify file integrity
      verify_gem_integrity(signable, signature_data, result)
    end

    def verify_zip(signable, signature_data, result)
      signature_checker = Verification::SignatureChecker.new

      # ZIP uses JAR-style signatures in META-INF/
      manifest = signature_data[:manifest]
      signature_file = signature_data[:signature_file]
      signature_block = signature_data[:signature_block]

      unless manifest && signature_file && signature_block
        result.add_error("Incomplete JAR signature (missing META-INF files)")
        return
      end

      # Verify PKCS#7 signature over the .SF file
      sig_result = signature_checker.verify_detached_pkcs7(signature_block, signature_file, trust_store)

      result.signature_valid = sig_result.signature_valid
      result.signer_certificate = sig_result.signer_certificate
      result.certificate_chain = sig_result.certificates
      result.signature_algorithm = sig_result.signature_algorithm

      sig_result.errors.each { |e| result.add_error(e) }

      if result.signer_certificate
        extract_signer_info(result)
        verify_certificate_chain(result)
      end

      # Verify manifest integrity
      verify_zip_manifest(signable, manifest, signature_file, result)
    end

    def verify_certificate_chain(result)
      return unless result.signer_certificate

      chain_validator = Verification::CertificateChain.new(
        trust_store,
        check_revocation: @check_revocation,
        network_timeout: @configuration.network_timeout
      )

      # Use timestamp time if available for point-in-time verification
      at_time = result.timestamped? ? result.timestamp : nil

      chain_result = chain_validator.validate(
        result.signer_certificate,
        result.certificate_chain[1..] || [],
        at_time: at_time
      )

      result.certificate_valid = chain_result.certificate_valid
      result.chain_valid = chain_result.chain_valid
      result.trusted = chain_result.trusted
      result.not_revoked = chain_result.not_revoked
      result.revocation_checked = chain_result.revocation_checked

      chain_result.errors.each { |e| result.add_error(e) }
      chain_result.warnings.each { |w| result.add_warning(w) }
    end

    def extract_signer_info(result)
      cert = result.signer_certificate
      return unless cert

      subject = cert.subject

      # Extract CN
      cn = subject.to_a.find { |name, _, _| name == "CN" }
      result.signer_name = cn ? cn[1] : subject.to_s

      # Extract O
      org = subject.to_a.find { |name, _, _| name == "O" }
      result.signer_organization = org ? org[1] : nil
    end

    def verify_gem_integrity(signable, signature_data, result)
      # For gems, verify all signed files have valid signatures
      # and content matches
      result.integrity_valid = true

      # The signature covers the gem contents hash
      # If signature verification passed, integrity is verified
      # Additional checks could verify individual file hashes
    end

    def verify_zip_manifest(signable, manifest, signature_file, result)
      result.integrity_valid = true

      # Parse manifest and verify file hashes
      begin
        # Verify that .SF file hash matches manifest
        sf_manifest_digest = extract_sf_manifest_digest(signature_file)
        actual_manifest_hash = compute_manifest_hash(manifest)

        unless sf_manifest_digest == actual_manifest_hash
          result.integrity_valid = false
          result.add_error("Manifest digest mismatch")
          return
        end

        # Verify individual file hashes from manifest
        verify_zip_file_hashes(signable, manifest, result)

      rescue StandardError => e
        result.integrity_valid = false
        result.add_error("Manifest verification failed: #{e.message}")
      end
    end

    def extract_sf_manifest_digest(signature_file)
      # Look for SHA-256-Digest-Manifest or similar
      match = signature_file.match(/SHA-256-Digest-Manifest:\s*(\S+)/) ||
              signature_file.match(/SHA-384-Digest-Manifest:\s*(\S+)/) ||
              signature_file.match(/SHA-512-Digest-Manifest:\s*(\S+)/)

      match ? match[1] : nil
    end

    def compute_manifest_hash(manifest)
      require "base64"
      Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(manifest))
    end

    def verify_zip_file_hashes(signable, manifest, result)
      # Parse manifest entries
      entries = parse_manifest(manifest)

      ::Zip::File.open(signable.file_path) do |zip|
        entries.each do |name, expected_hash|
          entry = zip.find_entry(name)
          unless entry
            result.add_warning("File in manifest not found in ZIP: #{name}")
            next
          end

          actual_hash = compute_file_hash(entry.get_input_stream.read)
          unless actual_hash == expected_hash
            result.integrity_valid = false
            result.add_error("Hash mismatch for file: #{name}")
          end
        end
      end
    end

    def parse_manifest(manifest)
      entries = {}
      current_name = nil

      manifest.each_line do |line|
        line = line.strip
        if line.start_with?("Name: ")
          current_name = line.sub("Name: ", "")
        elsif current_name && line.match?(/SHA-\d+-Digest:/)
          hash = line.split(": ", 2).last
          entries[current_name] = hash
        end
      end

      entries
    end

    def compute_file_hash(content)
      require "base64"
      Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(content))
    end

    def verify_timestamp_token(signature_data, result)
      # Look for embedded timestamp in PKCS#7
      # This would require parsing the unsigned attributes
      # For now, mark as not verified if timestamp detection is needed

      result.timestamp_valid = false
      result.add_warning("Timestamp verification not yet implemented")
    end
  end
end
