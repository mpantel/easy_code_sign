# frozen_string_literal: true

module EasyCodeSign
  module Pdf
    # Adapts a pre-fetched timestamp token for HexaPDF's SignedDataCreator.
    #
    # HexaPDF's SignedDataCreator calls `timestamp_handler.sign(io, byte_range)`
    # and embeds the return value as the id-aa-timeStampToken unsigned attribute.
    # This handler returns the DER bytes of an already-obtained token rather than
    # making a live TSA request.
    #
    # Supports both eager (TimestampToken) and lazy (Proc) modes:
    #   - Eager: TimestampHandler.new(token)       — token already available
    #   - Lazy:  TimestampHandler.new(-> { token }) — token resolved at sign time
    #
    class TimestampHandler
      def initialize(timestamp_token)
        @timestamp_token = timestamp_token
      end

      # Called by HexaPDF's SignedDataCreator#create_unsigned_attrs
      # @param _io [IO] ignored — we already have the token
      # @param _byte_range [Array] ignored
      # @return [String, nil] DER-encoded timestamp token
      def sign(_io, _byte_range)
        token = @timestamp_token.respond_to?(:call) ? @timestamp_token.call : @timestamp_token
        token&.token_der
      end
    end
  end
end
