# frozen_string_literal: true

require "openssl"
require "securerandom"

module EasyCodeSign
  module Timestamp
    # RFC 3161 Timestamp Request builder
    #
    # Creates a TimeStampReq ASN.1 structure for submission to a TSA.
    #
    # @example
    #   request = Timestamp::Request.new(signature_data, algorithm: :sha256)
    #   der_bytes = request.to_der
    #
    class Request
      # OIDs for hash algorithms
      HASH_ALGORITHM_OIDS = {
        sha256: "2.16.840.1.101.3.4.2.1",
        sha384: "2.16.840.1.101.3.4.2.2",
        sha512: "2.16.840.1.101.3.4.2.3",
        sha1: "1.3.14.3.2.26" # Legacy, not recommended
      }.freeze

      attr_reader :data, :algorithm, :nonce, :cert_req, :policy_oid

      # Create a new timestamp request
      #
      # @param data [String] the data to timestamp (typically a signature)
      # @param algorithm [Symbol] hash algorithm (:sha256, :sha384, :sha512)
      # @param cert_req [Boolean] request signing certificate in response
      # @param policy_oid [String, nil] optional TSA policy OID
      #
      def initialize(data, algorithm: :sha256, cert_req: true, policy_oid: nil)
        @data = data
        @algorithm = algorithm
        @cert_req = cert_req
        @policy_oid = policy_oid
        @nonce = generate_nonce
      end

      # Get the message digest of the data
      # @return [String] hash bytes
      def message_imprint_hash
        digest_class.digest(data)
      end

      # Encode the request as DER
      # @return [String] DER-encoded TimeStampReq
      def to_der
        # TimeStampReq ::= SEQUENCE {
        #   version          INTEGER { v1(1) },
        #   messageImprint   MessageImprint,
        #   reqPolicy        TSAPolicyId OPTIONAL,
        #   nonce            INTEGER OPTIONAL,
        #   certReq          BOOLEAN DEFAULT FALSE,
        #   extensions       [0] IMPLICIT Extensions OPTIONAL
        # }

        seq = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(1), # version
          message_imprint_asn1,
          # reqPolicy omitted if nil
          policy_oid ? OpenSSL::ASN1::ObjectId.new(policy_oid) : nil,
          OpenSSL::ASN1::Integer.new(nonce),
          OpenSSL::ASN1::Boolean.new(cert_req)
        ].compact)

        seq.to_der
      end

      # Get the hash algorithm OID
      # @return [String]
      def algorithm_oid
        HASH_ALGORITHM_OIDS[algorithm] or
          raise ArgumentError, "Unsupported algorithm: #{algorithm}"
      end

      private

      def message_imprint_asn1
        # MessageImprint ::= SEQUENCE {
        #   hashAlgorithm    AlgorithmIdentifier,
        #   hashedMessage    OCTET STRING
        # }

        algo_id = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new(algorithm_oid),
          OpenSSL::ASN1::Null.new(nil)
        ])

        OpenSSL::ASN1::Sequence.new([
          algo_id,
          OpenSSL::ASN1::OctetString.new(message_imprint_hash)
        ])
      end

      def digest_class
        case algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        when :sha1 then OpenSSL::Digest::SHA1
        else raise ArgumentError, "Unsupported algorithm: #{algorithm}"
        end
      end

      def generate_nonce
        # Generate a random 64-bit nonce
        SecureRandom.random_number(2**64)
      end
    end
  end
end
