# frozen_string_literal: true
# backtick_javascript: true

require "native"
require "promise"
require "easy_sign/messaging"

# Injected page script that exposes window.EasySign API
# This runs in the page context, not the extension context
module EasySign
  class API
    DEFAULT_TIMEOUT = 120_000 # 2 minutes

    def initialize
      @pending_requests = {}
      setup_message_listener
    end

    # Check if EasySign extension is available and token is connected
    # @return [Promise] Resolves with availability info
    def is_available
      Promise.new do |resolve, reject|
        request = create_request(Messaging::Types::AVAILABILITY_REQUEST, {})
        send_request(request, resolve, reject, 10_000) # 10 second timeout for availability check
      end
    end

    # Sign a PDF document
    # @param pdf_blob [Blob] The PDF file as a Blob
    # @param options [Hash] Signing options
    # @option options [String] :reason Reason for signing
    # @option options [String] :location Location of signing
    # @option options [Boolean] :visible_signature Add visible signature annotation
    # @option options [String] :signature_position Position (top_left, top_right, bottom_left, bottom_right)
    # @option options [Integer] :signature_page Page number for signature
    # @option options [Boolean] :timestamp Add RFC 3161 timestamp
    # @return [Promise] Resolves with signed PDF Blob
    def sign(pdf_blob, options = {})
      Promise.new do |resolve, reject|
        # Convert Blob to Base64
        blob_to_base64(pdf_blob).then do |base64_data|
          request = create_request(
            Messaging::Types::SIGN_REQUEST,
            { pdf_data: base64_data, options: normalize_options(options) }
          )

          # Wrap resolve to convert Base64 back to Blob
          wrapped_resolve = ->(response) {
            if response[:payload] && response[:payload][:signedPdfData]
              base64_to_blob(response[:payload][:signedPdfData], "application/pdf").then do |blob|
                resolve.call({
                  blob: blob,
                  signer_name: response[:payload][:signerName],
                  signed_at: response[:payload][:signedAt],
                  timestamped: response[:payload][:timestamped]
                })
              end
            else
              resolve.call(response)
            end
          }

          send_request(request, wrapped_resolve, reject)
        end.fail do |error|
          reject.call(error)
        end
      end
    end

    # Verify a signed PDF document
    # @param pdf_blob [Blob] The signed PDF file as a Blob
    # @param options [Hash] Verification options
    # @option options [Boolean] :check_timestamp Verify timestamp (default: true)
    # @return [Promise] Resolves with verification result
    def verify(pdf_blob, options = {})
      Promise.new do |resolve, reject|
        blob_to_base64(pdf_blob).then do |base64_data|
          request = create_request(
            Messaging::Types::VERIFY_REQUEST,
            {
              pdf_data: base64_data,
              check_timestamp: options[:check_timestamp] != false
            }
          )

          send_request(request, resolve, reject)
        end.fail do |error|
          reject.call(error)
        end
      end
    end

    # Cancel an ongoing signing operation
    # @param request_id [String] The request ID to cancel
    # @return [Promise]
    def cancel(request_id)
      Promise.new do |resolve, reject|
        request = {
          type: Messaging::Types::CANCEL_REQUEST,
          request_id: request_id,
          target: Messaging::Targets::EXTENSION
        }

        `window.postMessage(#{request.to_n}, '*')`
        resolve.call({ cancelled: true })
      end
    end

    private

    def setup_message_listener
      `window.addEventListener('message', (event) => {
        if (event.source !== window) return;
        if (!event.data || event.data.target !== #{Messaging::Targets::PAGE.to_n}) return;

        #{handle_response(`event.data`)}
      })`
    end

    def handle_response(data)
      request_id = data[:request_id] || `data.requestId` || `data.request_id`
      callbacks = @pending_requests.delete(request_id)

      return unless callbacks

      resolve = callbacks[:resolve]
      reject = callbacks[:reject]

      # Clear timeout
      `clearTimeout(#{callbacks[:timeout_id]})` if callbacks[:timeout_id]

      error = data[:error] || `data.error`
      if error
        error_obj = `new Error(#{error[:message] || `error.message` || 'Unknown error'})`
        `#{error_obj}.code = #{error[:code] || `error.code`}`
        reject.call(error_obj)
      else
        resolve.call(data)
      end
    end

    def create_request(type, payload)
      {
        type: type,
        request_id: generate_request_id,
        payload: payload,
        target: Messaging::Targets::EXTENSION
      }
    end

    def send_request(request, resolve, reject, timeout = DEFAULT_TIMEOUT)
      request_id = request[:request_id]

      # Set up timeout
      timeout_id = `setTimeout(() => {
        #{handle_timeout(request_id)}
      }, #{timeout})`

      @pending_requests[request_id] = {
        resolve: resolve,
        reject: reject,
        timeout_id: timeout_id
      }

      `window.postMessage(#{request.to_n}, '*')`
    end

    def handle_timeout(request_id)
      callbacks = @pending_requests.delete(request_id)
      return unless callbacks

      error = `new Error('Operation timed out')`
      `#{error}.code = 'TIMEOUT'`
      callbacks[:reject].call(error)
    end

    def generate_request_id
      `crypto.randomUUID ? crypto.randomUUID() :
        Date.now().toString(36) + Math.random().toString(36).substr(2)`
    end

    def normalize_options(options)
      # Convert Ruby-style options to camelCase for native host
      {
        reason: options[:reason],
        location: options[:location],
        visibleSignature: options[:visible_signature],
        signaturePosition: options[:signature_position],
        signaturePage: options[:signature_page],
        timestamp: options[:timestamp],
        timestampAuthority: options[:timestamp_authority]
      }.compact
    end

    def blob_to_base64(blob)
      Promise.new do |resolve, reject|
        `const reader = new FileReader();
         reader.onload = function() {
           // Remove data URL prefix to get just base64
           const base64 = reader.result.split(',')[1];
           #{resolve.call(`base64`)}
         };
         reader.onerror = function() {
           #{reject.call(`reader.error`)}
         };
         reader.readAsDataURL(#{blob});`
      end
    end

    def base64_to_blob(base64, mime_type)
      Promise.new do |resolve, _reject|
        `const byteCharacters = atob(#{base64});
         const byteNumbers = new Array(byteCharacters.length);
         for (let i = 0; i < byteCharacters.length; i++) {
           byteNumbers[i] = byteCharacters.charCodeAt(i);
         }
         const byteArray = new Uint8Array(byteNumbers);
         const blob = new Blob([byteArray], { type: #{mime_type} });
         #{resolve.call(`blob`)};`
      end
    end
  end
end

# Expose to window object
`window.EasySign = #{EasySign::API.new.to_n}`

# Also expose individual methods directly for convenience
`window.EasySign.sign = function(blob, options) {
  return #{EasySign::API.new}.sign(blob, options || {});
};
window.EasySign.verify = function(blob, options) {
  return #{EasySign::API.new}.verify(blob, options || {});
};
window.EasySign.isAvailable = function() {
  return #{EasySign::API.new}.is_available();
};`

puts "EasySign API injected into page"
