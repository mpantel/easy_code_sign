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

    desc "sign FILE", "Sign a file (gem or zip) using hardware token"
    long_desc <<~DESC
      Sign a file using a hardware security token (HSM/smart card).

      Supported file types:
        - Ruby gems (.gem)
        - ZIP archives (.zip, .jar, .apk, .war, .ear)

      The signature is embedded in the file. For gems, this creates
      PKCS#7 detached signatures compatible with `gem cert`.
    DESC
    option :output, type: :string, aliases: "-o", desc: "Output file path (default: overwrite input)"
    option :timestamp, type: :boolean, default: false, aliases: "-t", desc: "Add RFC 3161 timestamp"
    option :tsa, type: :string, desc: "Timestamp authority URL"
    option :algorithm, type: :string, default: "sha256", desc: "Hash algorithm (sha256, sha384, sha512)"
    option :provider, type: :string, default: "safenet", desc: "Token provider (safenet)"
    option :library, type: :string, desc: "Path to PKCS#11 library"
    option :slot, type: :numeric, default: 0, desc: "Token slot index"
    def sign(file)
      configure_from_options

      pin = prompt_for_pin
      algorithm = :"#{options[:algorithm]}_rsa"

      say "Signing #{file}...", :cyan unless options[:quiet]

      result = EasyCodeSign.sign(
        file,
        pin: pin,
        output_path: options[:output],
        timestamp: options[:timestamp],
        algorithm: algorithm
      )

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

    def say_error(message)
      say "Error: #{message}", :red
    end
  end
end
