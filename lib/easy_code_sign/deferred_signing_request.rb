# frozen_string_literal: true

require "base64"
require "time"

module EasyCodeSign
  # Serializable data object returned by Phase 1 of deferred PDF signing.
  #
  # Contains the digest computed from the PDF's ByteRange content, along with
  # all metadata needed to finalize the signature in Phase 2.
  #
  # @example Prepare and serialize
  #   request = EasyCodeSign.prepare_pdf("doc.pdf", pin: "1234")
  #   json = request.to_h.to_json
  #
  # @example Deserialize and finalize
  #   restored = DeferredSigningRequest.from_h(JSON.parse(json))
  #   EasyCodeSign.finalize_pdf(restored, raw_signature)
  #
  class DeferredSigningRequest
    attr_reader :digest,
                :digest_algorithm,
                :prepared_pdf_path,
                :byte_range,
                :certificate,
                :certificate_chain,
                :estimated_size,
                :signing_time,
                :created_at

    def initialize(digest:, digest_algorithm:, prepared_pdf_path:, byte_range:,
                   certificate:, certificate_chain:, estimated_size:,
                   signing_time:, created_at: Time.now)
      @digest = digest
      @digest_algorithm = digest_algorithm.to_sym
      @prepared_pdf_path = prepared_pdf_path
      @byte_range = byte_range
      @certificate = certificate
      @certificate_chain = certificate_chain
      @estimated_size = estimated_size
      @signing_time = signing_time
      @created_at = created_at
    end

    # Hex-encoded digest for display and CLI output
    # @return [String]
    def digest_hex
      digest.unpack1("H*")
    end

    # Base64-encoded digest for WebCrypto / Fortify consumption
    # @return [String]
    def digest_base64
      Base64.strict_encode64(digest)
    end

    # Serialize to a Hash suitable for JSON transport.
    # Binary fields are Base64-encoded, certificates are PEM-encoded.
    # @return [Hash]
    def to_h
      {
        "digest" => digest_base64,
        "digest_algorithm" => digest_algorithm.to_s,
        "prepared_pdf_path" => prepared_pdf_path,
        "byte_range" => byte_range,
        "certificate" => certificate.to_pem,
        "certificate_chain" => certificate_chain.map(&:to_pem),
        "estimated_size" => estimated_size,
        "signing_time" => signing_time.iso8601,
        "created_at" => created_at.iso8601
      }
    end

    # Deserialize from a Hash (as produced by #to_h / JSON.parse).
    # @param hash [Hash] serialized request
    # @return [DeferredSigningRequest]
    def self.from_h(hash)
      new(
        digest: Base64.strict_decode64(hash["digest"]),
        digest_algorithm: hash["digest_algorithm"].to_sym,
        prepared_pdf_path: hash["prepared_pdf_path"],
        byte_range: hash["byte_range"],
        certificate: OpenSSL::X509::Certificate.new(hash["certificate"]),
        certificate_chain: hash["certificate_chain"].map { |pem| OpenSSL::X509::Certificate.new(pem) },
        estimated_size: hash["estimated_size"],
        signing_time: Time.parse(hash["signing_time"]),
        created_at: Time.parse(hash["created_at"])
      )
    end
  end
end
