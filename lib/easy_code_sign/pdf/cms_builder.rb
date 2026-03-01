# frozen_string_literal: true

require "openssl"

module EasyCodeSign
  module Pdf
    # Builds a detached CMS SignedData structure for PDF signing (adbe.pkcs7.detached).
    #
    # This is a pure-OpenSSL/MIT implementation that does not require HexaPDF.
    # It uses OpenSSL ASN.1 primitives to assemble the CMS structure and supports
    # callback-based signing (HSM, hardware token) via a sign_bytes(hash) block.
    #
    # The block receives SHA256(signed_attrs_DER) and must return raw RSA signature bytes.
    # This matches HexaPDF's external_signing convention so providers are interchangeable.
    #
    # @example
    #   builder = CmsBuilder.new(certificate: cert, certificate_chain: [])
    #   cms_der = builder.build(byterange_content) { |hash| private_key.sign_raw("SHA256", hash) }
    #
    class CmsBuilder
      # OIDs used in PDF CMS signatures
      OID_DATA           = "1.2.840.113549.1.7.1"   # id-data
      OID_SIGNED_DATA    = "1.2.840.113549.1.7.2"   # id-signedData
      OID_CONTENT_TYPE   = "1.2.840.113549.1.9.3"   # id-contentType
      OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"   # id-messageDigest
      OID_SIGNING_TIME   = "1.2.840.113549.1.9.5"   # id-signingTime
      OID_SHA256         = "2.16.840.1.101.3.4.2.1" # id-sha256
      OID_RSA            = "1.2.840.113549.1.1.1"   # rsaEncryption
      OID_SHA256_RSA     = "1.2.840.113549.1.1.11"  # sha256WithRSAEncryption

      # @param certificate [OpenSSL::X509::Certificate] signer certificate
      # @param certificate_chain [Array<OpenSSL::X509::Certificate>] extra certs (intermediate CA etc.)
      # @param signing_time [Time] time to embed in signed attributes (default: now)
      def initialize(certificate:, certificate_chain: [], signing_time: nil)
        @certificate       = certificate
        @certificate_chain = certificate_chain
        @signing_time      = signing_time || Time.now
      end

      # Build CMS SignedData DER for the given ByteRange content.
      #
      # @param data [String] concatenated ByteRange bytes from the PDF
      # @yield [hash] SHA256 hash of the signed-attributes DER (binary String)
      # @yieldreturn [String] raw RSA signature bytes (PKCS#1 v1.5)
      # @return [String] DER-encoded CMS ContentInfo
      def build(data)
        raise ArgumentError, "sign_bytes block required" unless block_given?

        message_digest   = OpenSSL::Digest::SHA256.digest(data)
        signed_attrs_der = build_signed_attrs_der(message_digest)

        # Hash of the DER-encoded signed attributes SET — this is what sign_raw signs
        hash      = OpenSSL::Digest::SHA256.digest(signed_attrs_der)
        signature = yield(hash)

        build_content_info(signature, signed_attrs_der)
      end

      private

      # Construct the signed attributes as a DER-encoded SET.
      # The result is hashed and signed; then stored as [0] IMPLICIT in SignerInfo.
      def build_signed_attrs_der(message_digest)
        attrs = [
          attribute(OID_CONTENT_TYPE, OpenSSL::ASN1::ObjectId.new(OID_DATA)),
          attribute(OID_MESSAGE_DIGEST, OpenSSL::ASN1::OctetString.new(message_digest)),
          attribute(OID_SIGNING_TIME, OpenSSL::ASN1::UTCTime.new(@signing_time))
        ]
        OpenSSL::ASN1::Set.new(attrs).to_der
      end

      # Build a CMS Attribute: SEQUENCE { OID, SET { value } }
      def attribute(oid_str, value)
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new(oid_str),
          OpenSSL::ASN1::Set.new([value])
        ])
      end

      # Build the top-level CMS ContentInfo wrapping SignedData
      def build_content_info(signature, signed_attrs_der)
        signed_data = build_signed_data(signature, signed_attrs_der)

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new(OID_SIGNED_DATA),
          OpenSSL::ASN1::ASN1Data.new([signed_data], 0, :CONTEXT_SPECIFIC) # [0] EXPLICIT
        ]).to_der
      end

      def build_signed_data(signature, signed_attrs_der)
        sha256_alg  = algorithm_identifier(OID_SHA256)
        rsa_alg     = algorithm_identifier(OID_RSA)
        signer_info = build_signer_info(signature, signed_attrs_der, sha256_alg, rsa_alg)

        # certificates [0] IMPLICIT — DER of each cert wrapped as context-specific
        all_certs  = [@certificate, *@certificate_chain]
        cert_nodes = all_certs.map { |c| OpenSSL::ASN1.decode(c.to_der) }
        certs_tagged = OpenSSL::ASN1::ASN1Data.new(cert_nodes, 0, :CONTEXT_SPECIFIC)

        # encapContentInfo: just the eContentType, no eContent (detached)
        encap = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(OID_DATA)])

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(1)), # version 1
          OpenSSL::ASN1::Set.new([sha256_alg]),           # digestAlgorithms
          encap,                                          # encapContentInfo
          certs_tagged,                                   # certificates [0]
          OpenSSL::ASN1::Set.new([signer_info])           # signerInfos
        ])
      end

      def build_signer_info(signature, signed_attrs_der, sha256_alg, rsa_alg)
        # IssuerAndSerialNumber
        issuer_and_serial = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1.decode(@certificate.issuer.to_der),
          OpenSSL::ASN1::Integer.new(@certificate.serial)
        ])

        # signedAttrs stored as [0] IMPLICIT (same bytes as SET but tag = 0xA0)
        parsed_set     = OpenSSL::ASN1.decode(signed_attrs_der)
        signed_attrs_0 = OpenSSL::ASN1::ASN1Data.new(parsed_set.value, 0, :CONTEXT_SPECIFIC)

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(1)), # version 1
          issuer_and_serial,
          sha256_alg,                                     # digestAlgorithm
          signed_attrs_0,                                 # signedAttrs [0] IMPLICIT
          rsa_alg,                                        # signatureAlgorithm
          OpenSSL::ASN1::OctetString.new(signature)       # signature
        ])
      end

      # AlgorithmIdentifier SEQUENCE { OID, NULL }
      def algorithm_identifier(oid_str)
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new(oid_str),
          OpenSSL::ASN1::Null.new(nil)
        ])
      end
    end
  end
end
