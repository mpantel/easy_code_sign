# frozen_string_literal: true

module EasyCodeSign
  module Pdf
    # Handles embedding RFC 3161 timestamps in PDF signatures
    #
    # PDF signatures can include timestamps in the unsigned attributes of the
    # CMS SignedData structure (PAdES-B compliance).
    #
    class TimestampHandler
      attr_reader :timestamp_token

      def initialize(timestamp_token)
        @timestamp_token = timestamp_token
      end

      # Called by HexaPDF to embed timestamp in signature
      # @param signature_value [String] the signature value to timestamp
      # @return [String] timestamp token DER bytes
      def timestamp(signature_value)
        if @timestamp_token
          @timestamp_token.token
        else
          nil
        end
      end
    end
  end
end
