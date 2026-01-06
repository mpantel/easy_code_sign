# frozen_string_literal: true

require "net/http"
require "uri"

module EasyCodeSign
  module Timestamp
    # RFC 3161 Timestamp Authority Client
    #
    # Communicates with a TSA to obtain timestamp tokens for signatures.
    #
    # @example
    #   client = Timestamp::Client.new("http://timestamp.digicert.com")
    #   token = client.timestamp(signature_bytes, algorithm: :sha256)
    #
    class Client
      CONTENT_TYPE = "application/timestamp-query"
      ACCEPT_TYPE = "application/timestamp-reply"

      attr_reader :url, :timeout, :username, :password

      # Common TSA URLs for reference
      KNOWN_TSAS = {
        digicert: "http://timestamp.digicert.com",
        globalsign: "http://timestamp.globalsign.com/tsa/r6advanced1",
        sectigo: "http://timestamp.sectigo.com",
        comodo: "http://timestamp.comodoca.com",
        entrust: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
        ssl_com: "http://ts.ssl.com"
      }.freeze

      # Create a new TSA client
      #
      # @param url [String] TSA URL
      # @param timeout [Integer] HTTP timeout in seconds
      # @param username [String, nil] HTTP Basic auth username
      # @param password [String, nil] HTTP Basic auth password
      #
      def initialize(url, timeout: 30, username: nil, password: nil)
        @url = url
        @timeout = timeout
        @username = username
        @password = password
      end

      # Request a timestamp for data
      #
      # @param data [String] data to timestamp (typically a signature)
      # @param algorithm [Symbol] hash algorithm (:sha256, :sha384, :sha512)
      # @param cert_req [Boolean] request TSA certificate in response
      # @return [TimestampToken] the timestamp token
      # @raise [TimestampAuthorityError] if TSA request fails
      # @raise [InvalidTimestampError] if response is invalid
      #
      def timestamp(data, algorithm: :sha256, cert_req: true)
        request = Request.new(data, algorithm: algorithm, cert_req: cert_req)
        response = send_request(request)

        validate_response!(response, request)

        TimestampToken.new(
          token_der: response.token_der,
          timestamp: response.timestamp,
          serial_number: response.serial_number,
          policy_oid: response.policy_oid,
          tsa_url: url
        )
      end

      # Check if the TSA is reachable
      # @return [Boolean]
      def available?
        uri = URI.parse(url)
        http = build_http(uri)
        http.open_timeout = 5
        http.read_timeout = 5

        response = http.head(uri.path.empty? ? "/" : uri.path)
        response.is_a?(Net::HTTPSuccess) || response.is_a?(Net::HTTPMethodNotAllowed)
      rescue StandardError
        false
      end

      private

      def send_request(request)
        uri = URI.parse(url)
        http = build_http(uri)

        http_request = Net::HTTP::Post.new(uri.path.empty? ? "/" : uri.path)
        http_request["Content-Type"] = CONTENT_TYPE
        http_request["Accept"] = ACCEPT_TYPE
        http_request.body = request.to_der

        if username && password
          http_request.basic_auth(username, password)
        end

        response = http.request(http_request)

        unless response.is_a?(Net::HTTPSuccess)
          raise TimestampAuthorityError.new(
            "TSA returned HTTP #{response.code}: #{response.message}",
            http_status: response.code.to_i
          )
        end

        Response.parse(response.body)
      rescue Timeout::Error, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
        raise TimestampAuthorityError, "Failed to connect to TSA: #{e.message}"
      rescue SocketError => e
        raise TimestampAuthorityError, "DNS resolution failed for TSA: #{e.message}"
      end

      def build_http(uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = timeout
        http.read_timeout = timeout

        if http.use_ssl?
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        end

        http
      end

      def validate_response!(response, request)
        unless response.success?
          raise TimestampAuthorityError, response.error_message
        end

        unless response.nonce_matches?(request.nonce)
          raise InvalidTimestampError, "Nonce mismatch: response nonce does not match request"
        end

        # Verify message imprint matches
        if response.message_imprint_hash != request.message_imprint_hash
          raise InvalidTimestampError, "Message imprint mismatch: TSA timestamped different data"
        end
      end
    end

    # Represents a timestamp token obtained from a TSA
    class TimestampToken
      attr_reader :token_der, :timestamp, :serial_number, :policy_oid, :tsa_url

      def initialize(token_der:, timestamp:, serial_number:, policy_oid:, tsa_url:)
        @token_der = token_der
        @timestamp = timestamp
        @serial_number = serial_number
        @policy_oid = policy_oid
        @tsa_url = tsa_url
      end

      # Get the timestamp as ISO 8601 string
      # @return [String]
      def timestamp_iso8601
        timestamp&.iso8601
      end

      # Get the PKCS#7 structure
      # @return [OpenSSL::PKCS7]
      def pkcs7
        @pkcs7 ||= OpenSSL::PKCS7.new(token_der)
      end

      # Get the TSA signing certificate (if included in response)
      # @return [OpenSSL::X509::Certificate, nil]
      def tsa_certificate
        pkcs7.certificates&.first
      end

      def to_h
        {
          timestamp: timestamp_iso8601,
          serial_number: serial_number,
          policy_oid: policy_oid,
          tsa_url: tsa_url
        }
      end
    end
  end
end
