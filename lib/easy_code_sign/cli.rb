# frozen_string_literal: true

require "thor"

module EasyCodeSign
  # Command-line interface for EasyCodeSign
  #
  # Provides commands for signing and verifying files using hardware tokens.
  #
  # @example
  #   $ easysign sign my_gem-1.0.0.gem --pin 1234
  #   $ easysign verify signed.gem
  #   $ easysign list-slots
  #
  class CLI < Thor
    class_option :verbose, type: :boolean, aliases: "-v", desc: "Enable verbose output"
    class_option :quiet, type: :boolean, aliases: "-q", desc: "Suppress non-essential output"

    def self.exit_on_failure?
      true
    end

    desc "sign FILE", "Sign a file (gem, zip, or PDF) using hardware token"
    long_desc <<~DESC
      Sign a file using a hardware security token (HSM/smart card).

      Supported file types:
        - Ruby gems (.gem)
        - ZIP archives (.zip, .jar, .apk, .war, .ear)
        - PDF documents (.pdf)

      The signature is embedded in the file. For gems, this creates
      PKCS#7 detached signatures. For PDFs, use --visible-signature
      to add a visible signature annotation.
    DESC
    option :output, type: :string, aliases: "-o", desc: "Output file path (default: overwrite input)"
    option :timestamp, type: :boolean, default: false, aliases: "-t", desc: "Add RFC 3161 timestamp"
    option :tsa, type: :string, desc: "Timestamp authority URL"
    option :algorithm, type: :string, default: "sha256", desc: "Hash algorithm (sha256, sha384, sha512)"
    option :provider, type: :string, default: "safenet", desc: "Token provider (safenet)"
    option :library, type: :string, desc: "Path to PKCS#11 library"
    option :slot, type: :numeric, default: 0, desc: "Token slot index"
    # PDF-specific options
    option :visible_signature, type: :boolean, default: false, desc: "[PDF] Add visible signature annotation"
    option :signature_page, type: :numeric, default: 1, desc: "[PDF] Page number for visible signature"
    option :signature_position, type: :string, default: "bottom_right", desc: "[PDF] Position (top_left, top_right, bottom_left, bottom_right)"
    option :signature_reason, type: :string, desc: "[PDF] Reason for signing"
    option :signature_location, type: :string, desc: "[PDF] Location of signing"
    def sign(file)
      configure_from_options

      pin = prompt_for_pin
      algorithm = :"#{options[:algorithm]}_rsa"

      say "Signing #{file}...", :cyan unless options[:quiet]

      # Build signing options, including PDF-specific ones
      sign_opts = {
        pin: pin,
        output_path: options[:output],
        timestamp: options[:timestamp],
        algorithm: algorithm
      }

      # Add PDF options if present
      if File.extname(file).downcase == ".pdf"
        sign_opts[:visible_signature] = options[:visible_signature]
        sign_opts[:signature_page] = options[:signature_page]
        sign_opts[:signature_position] = options[:signature_position]&.to_sym
        sign_opts[:signature_reason] = options[:signature_reason]
        sign_opts[:signature_location] = options[:signature_location]
      end

      result = EasyCodeSign.sign(file, **sign_opts)

      if options[:verbose]
        say "\nSigning complete:", :green
        say "  File: #{result.file_path}"
        say "  Signer: #{result.signer_name}"
        say "  Algorithm: #{result.algorithm}"
        say "  Timestamped: #{result.timestamped? ? 'Yes' : 'No'}"
        say "  Signed at: #{result.signed_at}"
      else
        say "Signed: #{result.file_path}", :green unless options[:quiet]
      end
    rescue EasyCodeSign::Error => e
      say_error "Signing failed: #{e.message}"
      exit 1
    end

    desc "verify FILE", "Verify a signed file"
    long_desc <<~DESC
      Verify the signature on a signed file.

      Checks:
        - Cryptographic signature validity
        - File integrity (not tampered)
        - Certificate validity and trust chain
        - Timestamp validity (if present)
    DESC
    option :trust_store, type: :string, desc: "Path to custom CA certificates"
    option :no_timestamp, type: :boolean, default: false, desc: "Skip timestamp verification"
    option :json, type: :boolean, default: false, desc: "Output result as JSON"
    def verify(file)
      trust_store = nil
      if options[:trust_store]
        trust_store = Verification::TrustStore.new
        if File.directory?(options[:trust_store])
          trust_store.add_directory(options[:trust_store])
        else
          trust_store.add_file(options[:trust_store])
        end
      end

      say "Verifying #{file}...", :cyan unless options[:quiet]

      result = EasyCodeSign.verify(
        file,
        check_timestamp: !options[:no_timestamp],
        trust_store: trust_store
      )

      if options[:json]
        require "json"
        say JSON.pretty_generate(result.to_h)
      else
        display_verification_result(result)
      end

      exit 1 unless result.valid?
    rescue EasyCodeSign::Error => e
      say_error "Verification failed: #{e.message}"
      exit 1
    end

    desc "list-slots", "List available token slots"
    long_desc <<~DESC
      List all available PKCS#11 token slots.

      Shows information about connected hardware tokens including:
        - Slot index
        - Token label
        - Manufacturer
        - Serial number
    DESC
    option :provider, type: :string, default: "safenet", desc: "Token provider"
    option :library, type: :string, desc: "Path to PKCS#11 library"
    def list_slots
      configure_from_options

      slots = EasyCodeSign.list_slots

      if slots.empty?
        say "No tokens found", :yellow
        return
      end

      say "Available token slots:", :cyan
      say ""

      slots.each do |slot|
        say "Slot #{slot[:index]}:"
        say "  Description: #{slot[:description]}"
        if slot[:token_present]
          say "  Token: #{slot[:token_label]}", :green
          say "  Manufacturer: #{slot[:manufacturer]}"
          say "  Serial: #{slot[:serial]}"
        else
          say "  Token: (not present)", :yellow
        end
        say ""
      end
    rescue EasyCodeSign::Error => e
      say_error "Failed to list slots: #{e.message}"
      exit 1
    end

    desc "prepare-pdf FILE", "Prepare a PDF for deferred (two-phase) signing"
    long_desc <<~DESC
      Phase 1 of deferred PDF signing.

      Prepares the PDF with a placeholder signature and outputs the digest
      that must be signed by an external signer (Fortify, WebCrypto, remote HSM).

      The prepared PDF and a JSON request file are written alongside the input.
      Send the digest to your external signing service, then use finalize-pdf
      to embed the real signature.
    DESC
    option :algorithm, type: :string, default: "sha256", desc: "Hash algorithm (sha256, sha384, sha512)"
    option :timestamp, type: :boolean, default: false, aliases: "-t", desc: "Reserve space for timestamp"
    option :provider, type: :string, default: "safenet", desc: "Token provider (safenet)"
    option :library, type: :string, desc: "Path to PKCS#11 library"
    option :slot, type: :numeric, default: 0, desc: "Token slot index"
    option :json, type: :boolean, default: false, desc: "Output result as JSON"
    option :signature_reason, type: :string, desc: "[PDF] Reason for signing"
    option :signature_location, type: :string, desc: "[PDF] Location of signing"
    def prepare_pdf(file)
      configure_from_options

      pin = prompt_for_pin

      say "Preparing #{file} for deferred signing...", :cyan unless options[:quiet]

      prepare_opts = {
        pin: pin,
        digest_algorithm: options[:algorithm],
        timestamp: options[:timestamp],
        signature_reason: options[:signature_reason],
        signature_location: options[:signature_location]
      }.compact

      request = EasyCodeSign.prepare_pdf(file, **prepare_opts)

      # Write request JSON for later use
      request_path = "#{request.prepared_pdf_path}.json"
      require "json"
      File.write(request_path, JSON.pretty_generate(request.to_h))

      if options[:json]
        say JSON.pretty_generate(request.to_h)
      else
        say "Prepared: #{request.prepared_pdf_path}", :green unless options[:quiet]
        say "Request saved: #{request_path}" unless options[:quiet]
        say "" unless options[:quiet]
        say "Digest (hex):    #{request.digest_hex}" unless options[:quiet]
        say "Digest (base64): #{request.digest_base64}" unless options[:quiet]
        say "" unless options[:quiet]
        say "Sign the digest externally, then run:", :cyan unless options[:quiet]
        say "  easysign finalize-pdf #{request.prepared_pdf_path} SIGNATURE_FILE" unless options[:quiet]
      end
    rescue EasyCodeSign::Error => e
      say_error "Prepare failed: #{e.message}"
      exit 1
    end

    desc "finalize-pdf PREPARED_PDF SIGNATURE_FILE", "Finalize a deferred PDF signature"
    long_desc <<~DESC
      Phase 2 of deferred PDF signing.

      Reads the prepared PDF and its accompanying .json request file, then
      embeds the raw signature from SIGNATURE_FILE into the PDF.

      SIGNATURE_FILE should contain the raw signature bytes (binary DER) produced
      by signing the digest from the prepare-pdf step.
    DESC
    option :timestamp, type: :boolean, default: false, aliases: "-t", desc: "Add RFC 3161 timestamp"
    option :tsa, type: :string, desc: "Timestamp authority URL"
    option :request_json, type: :string, desc: "Path to request JSON (default: PREPARED_PDF.json)"
    def finalize_pdf(prepared_pdf, signature_file)
      require "json"

      request_path = options[:request_json] || "#{prepared_pdf}.json"
      unless File.exist?(request_path)
        say_error "Request file not found: #{request_path}"
        say_error "Specify --request-json or ensure the .json file from prepare-pdf exists"
        exit 1
      end

      unless File.exist?(signature_file)
        say_error "Signature file not found: #{signature_file}"
        exit 1
      end

      configure_from_options

      say "Finalizing deferred signature on #{prepared_pdf}...", :cyan unless options[:quiet]

      request_hash = JSON.parse(File.read(request_path))
      request = EasyCodeSign::DeferredSigningRequest.from_h(request_hash)
      raw_signature = File.binread(signature_file)

      result = EasyCodeSign.finalize_pdf(request, raw_signature, timestamp: options[:timestamp])

      if options[:verbose]
        say "\nSigning complete:", :green
        say "  File: #{result.file_path}"
        say "  Signer: #{result.signer_name}"
        say "  Algorithm: #{result.algorithm}"
        say "  Timestamped: #{result.timestamped? ? 'Yes' : 'No'}"
        say "  Signed at: #{result.signed_at}"
      else
        say "Signed: #{result.file_path}", :green unless options[:quiet]
      end
    rescue EasyCodeSign::Error => e
      say_error "Finalize failed: #{e.message}"
      exit 1
    end

    desc "info FILE", "Show signature information for a signed file"
    long_desc <<~DESC
      Display detailed information about a file's signature without
      performing full verification.
    DESC
    def info(file)
      signable = EasyCodeSign.signable_for(file)
      signature = signable.extract_signature

      unless signature
        say "File is not signed", :yellow
        return
      end

      say "Signature information for #{file}:", :cyan
      say ""

      case signable
      when Signable::GemFile
        display_gem_signature_info(signature)
      when Signable::ZipFile
        display_zip_signature_info(signature)
      when Signable::PdfFile
        display_pdf_signature_info(signature)
      end
    rescue EasyCodeSign::Error => e
      say_error "Failed to read signature: #{e.message}"
      exit 1
    end

    desc "version", "Show version information"
    def version
      say "EasyCodeSign version #{EasyCodeSign::VERSION}"
    end

    map %w[-V --version] => :version

    private

    def configure_from_options
      EasyCodeSign.configure do |config|
        config.provider = options[:provider].to_sym if options[:provider]
        config.pkcs11_library = options[:library] if options[:library]
        config.slot_index = options[:slot] if options[:slot]
        config.timestamp_authority = options[:tsa] if options[:tsa]
      end
    end

    def prompt_for_pin
      say "Enter PIN: ", :cyan
      pin = $stdin.noecho(&:gets)&.chomp
      say "" # Newline after hidden input
      pin
    rescue Errno::ENOENT, NoMethodError
      # noecho not available (e.g., not a terminal)
      say "Enter PIN: ", :cyan
      $stdin.gets&.chomp
    end

    def display_verification_result(result)
      if result.valid?
        say "\n✓ Signature is VALID", :green
      else
        say "\n✗ Signature is INVALID", :red
      end

      say ""

      if result.signer_name
        say "Signer: #{result.signer_name}"
        say "Organization: #{result.signer_organization}" if result.signer_organization
      end

      say ""
      say "Checks:"
      display_check "  Signature", result.signature_valid?
      display_check "  Integrity", result.integrity_valid?
      display_check "  Certificate", result.certificate_valid?
      display_check "  Trust chain", result.chain_valid?
      display_check "  Trusted root", result.trusted?

      if result.timestamped?
        say ""
        say "Timestamp:"
        display_check "  Valid", result.timestamp_valid?
        say "  Time: #{result.timestamp&.iso8601}" if result.timestamp
        say "  Authority: #{result.timestamp_authority}" if result.timestamp_authority
      end

      unless result.errors.empty?
        say ""
        say "Errors:", :red
        result.errors.each { |e| say "  - #{e}", :red }
      end

      unless result.warnings.empty?
        say ""
        say "Warnings:", :yellow
        result.warnings.each { |w| say "  - #{w}", :yellow }
      end
    end

    def display_check(name, passed)
      if passed
        say "#{name}: ✓", :green
      else
        say "#{name}: ✗", :red
      end
    end

    def display_gem_signature_info(signature)
      say "Signature files:"
      signature.each_key do |name|
        say "  - #{name}"
      end
    end

    def display_zip_signature_info(signature)
      say "META-INF contents:"
      say "  - MANIFEST.MF: #{signature[:manifest] ? 'present' : 'missing'}"
      say "  - CERT.SF: #{signature[:signature_file] ? 'present' : 'missing'}"
      say "  - CERT.RSA: #{signature[:signature_block] ? 'present' : 'missing'}"
    end

    def display_pdf_signature_info(signature)
      say "PDF Signature:"
      say "  - SubFilter: #{signature[:sub_filter] || 'unknown'}"
      say "  - ByteRange: #{signature[:byte_range]&.inspect || 'unknown'}"
      say "  - Name: #{signature[:name]}" if signature[:name]
      say "  - Reason: #{signature[:reason]}" if signature[:reason]
      say "  - Location: #{signature[:location]}" if signature[:location]
      say "  - Signing Time: #{signature[:signing_time]}" if signature[:signing_time]
      say "  - Contact: #{signature[:contact_info]}" if signature[:contact_info]
    end

    def say_error(message)
      say "Error: #{message}", :red
    end
  end
end
