# frozen_string_literal: true

require_relative "lib/easy_code_sign/version"

Gem::Specification.new do |spec|
  spec.name = "easy_code_sign"
  spec.version = EasyCodeSign::VERSION
  spec.authors = ["michail"]
  spec.email = ["mpantel@aegean.gr"]

  spec.summary = "Sign and verify Ruby gems, ZIP files, and PDFs using hardware security tokens"
  spec.description = "A Ruby gem for code signing operations using hardware tokens (HSM/smart cards) " \
                     "via PKCS#11. Supports SafeNet eToken, RFC 3161 timestamping, PDF visible signatures, " \
                     "and signature verification."
  spec.homepage = "https://github.com/mpantel/easy_code_sign"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .rubocop.yml .claude/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "base64", "~> 0.2"
  spec.add_dependency "pdf-reader", "~> 2.0"   # MIT — used by native PDF signing backend
  spec.add_dependency "pkcs11", "~> 0.3"
  spec.add_dependency "rubyzip", "~> 2.3"
  spec.add_dependency "thor", "~> 1.3"

  # Development dependencies
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rubocop", "~> 1.21"
end
