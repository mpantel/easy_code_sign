# frozen_string_literal: true

module EasyCodeSign
  # Base error class for all EasyCodeSign errors
  class Error < StandardError; end

  # Raised when configuration is invalid or incomplete
  class ConfigurationError < Error; end

  # Base class for all token-related errors
  class TokenError < Error; end

  # Raised when the hardware token is not found or not connected
  class TokenNotFoundError < TokenError; end

  # Raised when PIN entry fails (wrong PIN, locked, etc.)
  class PinError < TokenError
    attr_reader :retries_remaining

    def initialize(message = "PIN verification failed", retries_remaining: nil)
      @retries_remaining = retries_remaining
      super(message)
    end
  end

  # Raised when the token is locked due to too many failed PIN attempts
  class TokenLockedError < TokenError; end

  # Raised when the requested certificate/key is not found on the token
  class KeyNotFoundError < TokenError; end

  # Raised when a PKCS#11 operation fails
  class Pkcs11Error < TokenError
    attr_reader :pkcs11_error_code

    def initialize(message, pkcs11_error_code: nil)
      @pkcs11_error_code = pkcs11_error_code
      super(message)
    end
  end

  # Base class for signing-related errors
  class SigningError < Error; end

  # Raised when the file to be signed cannot be read or is invalid
  class InvalidFileError < SigningError; end

  # Raised when signature generation fails
  class SignatureGenerationError < SigningError; end

  # Base class for verification-related errors
  class VerificationError < Error; end

  # Raised when signature verification fails cryptographically
  class InvalidSignatureError < VerificationError; end

  # Raised when the signed file has been tampered with
  class TamperedFileError < VerificationError; end

  # Raised when certificate chain validation fails
  class CertificateChainError < VerificationError
    attr_reader :certificate, :reason

    def initialize(message, certificate: nil, reason: nil)
      @certificate = certificate
      @reason = reason
      super(message)
    end
  end

  # Raised when a certificate has been revoked
  class CertificateRevokedError < CertificateChainError; end

  # Raised when a certificate has expired
  class CertificateExpiredError < CertificateChainError; end

  # Raised when the signing certificate is not trusted
  class UntrustedCertificateError < CertificateChainError; end

  # Base class for timestamp-related errors
  class TimestampError < Error; end

  # Raised when communication with the TSA fails
  class TimestampAuthorityError < TimestampError
    attr_reader :http_status

    def initialize(message, http_status: nil)
      @http_status = http_status
      super(message)
    end
  end

  # Raised when the TSA response is invalid or verification fails
  class InvalidTimestampError < TimestampError; end

  # Raised when a required timestamp is missing
  class MissingTimestampError < TimestampError; end
end
