# frozen_string_literal: true
# backtick_javascript: true

require "native"
require "easy_sign/messaging"

# Background service worker for EasySign browser extension
# Handles communication between content scripts and native messaging host
module EasySign
  class Background
    NATIVE_HOST_NAME = "com.easysign.host"

    def initialize
      @native_port = nil
      @pending_requests = {}
      @current_signing_request = nil
      setup_listeners
      puts "EasySign background service worker initialized"
    end

    def setup_listeners
      # Listen for messages from content scripts
      `chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        #{handle_message(`message`, `sender`, `sendResponse`)}
        return true; // Keep channel open for async response
      })`

      # Listen for connections (for popup communication)
      `chrome.runtime.onConnect.addListener((port) => {
        #{handle_port_connect(`port`)}
      })`
    end

    def handle_message(message, sender, send_response)
      type = message[:type] || `message.type`
      request_id = message[:request_id] || `message.requestId` || `message.request_id`

      case type
      when Messaging::Types::SIGN_REQUEST
        handle_sign_request(message, sender, send_response)
      when Messaging::Types::VERIFY_REQUEST
        handle_verify_request(message, sender, send_response)
      when Messaging::Types::AVAILABILITY_REQUEST
        handle_availability_request(send_response)
      when Messaging::Types::CANCEL_REQUEST
        handle_cancel_request(request_id, send_response)
      else
        send_error(send_response, request_id, Messaging::ErrorCodes::INTERNAL_ERROR,
                   "Unknown message type: #{type}")
      end
    end

    def handle_port_connect(port)
      port_name = `port.name`

      case port_name
      when "popup"
        setup_popup_port(port)
      end
    end

    def setup_popup_port(port)
      @popup_port = port

      `port.onMessage.addListener((message) => {
        #{handle_popup_message(`message`)}
      })`

      `port.onDisconnect.addListener(() => {
        #{handle_popup_disconnect}
      })`
    end

    def handle_popup_message(message)
      type = message[:type] || `message.type`

      case type
      when Messaging::Types::PIN_SUBMITTED
        pin = message[:pin] || `message.pin`
        complete_signing_with_pin(pin)
      when Messaging::Types::PIN_CANCELLED
        cancel_current_signing
      when Messaging::Types::POPUP_READY
        send_signing_context_to_popup
      end
    end

    def handle_popup_disconnect
      @popup_port = nil
      # If popup closes without submitting PIN, cancel the operation
      cancel_current_signing if @current_signing_request
    end

    def handle_sign_request(message, sender, send_response)
      payload = message[:payload] || `message.payload`

      # Validate origin
      origin = `sender.origin || sender.url`
      unless origin_allowed?(origin)
        send_error(send_response, message[:request_id],
                   Messaging::ErrorCodes::ORIGIN_NOT_ALLOWED,
                   "Origin not allowed: #{origin}")
        return
      end

      # Store the request for completion after PIN entry
      @current_signing_request = {
        message: message,
        sender: sender,
        send_response: send_response,
        payload: payload
      }

      # Open popup for PIN entry
      open_pin_popup
    end

    def handle_verify_request(message, sender, send_response)
      payload = message[:payload] || `message.payload`

      # Verification doesn't need PIN, send directly to native host
      ensure_native_connection do |error|
        if error
          send_error(send_response, message[:request_id],
                     Messaging::ErrorCodes::NATIVE_HOST_NOT_FOUND, error)
          return
        end

        native_message = {
          type: "verify",
          requestId: message[:request_id] || `message.requestId`,
          payload: {
            pdfData: payload[:pdf_data] || `payload.pdfData`,
            checkTimestamp: payload[:check_timestamp] != false
          }
        }

        send_to_native(native_message, send_response)
      end
    end

    def handle_availability_request(send_response)
      ensure_native_connection do |error|
        if error
          # Native host not available, but extension is
          response = Messaging.create_response(
            nil,
            Messaging::Types::AVAILABILITY_RESPONSE,
            { available: false, nativeHostInstalled: false, error: error }
          )
          `sendResponse(#{response.to_n})`
          return
        end

        native_message = { type: "check_availability", requestId: Messaging.generate_request_id }
        send_to_native(native_message, send_response)
      end
    end

    def handle_cancel_request(request_id, send_response)
      if @current_signing_request && @current_signing_request[:message][:request_id] == request_id
        cancel_current_signing
      end

      response = Messaging.create_response(request_id, "cancel_response", { cancelled: true })
      `sendResponse(#{response.to_n})`
    end

    def complete_signing_with_pin(pin)
      return unless @current_signing_request

      request = @current_signing_request
      message = request[:message]
      payload = request[:payload]
      send_response = request[:send_response]

      ensure_native_connection do |error|
        if error
          send_error(send_response, message[:request_id],
                     Messaging::ErrorCodes::NATIVE_HOST_NOT_FOUND, error)
          @current_signing_request = nil
          return
        end

        native_message = {
          type: "sign",
          requestId: message[:request_id] || `message.requestId`,
          payload: {
            pdfData: payload[:pdf_data] || `payload.pdfData`,
            pin: pin,
            options: payload[:options] || `payload.options` || {}
          }
        }

        send_to_native(native_message, send_response)
        @current_signing_request = nil
      end
    end

    def cancel_current_signing
      return unless @current_signing_request

      request = @current_signing_request
      send_response = request[:send_response]
      request_id = request[:message][:request_id]

      send_error(send_response, request_id, Messaging::ErrorCodes::CANCELLED, "Operation cancelled by user")
      @current_signing_request = nil
    end

    def send_signing_context_to_popup
      return unless @popup_port && @current_signing_request

      context = {
        type: "signing_context",
        origin: @current_signing_request[:sender] && `#{@current_signing_request[:sender]}.origin`,
        options: @current_signing_request[:payload][:options] || {}
      }

      `#{@popup_port}.postMessage(#{context.to_n})`
    end

    def open_pin_popup
      # Open extension popup programmatically
      `chrome.action.openPopup().catch((e) => {
        console.error('Failed to open popup:', e);
        // Fallback: create a new window
        chrome.windows.create({
          url: 'popup/popup.html',
          type: 'popup',
          width: 400,
          height: 300
        });
      })`
    end

    def ensure_native_connection(&block)
      if @native_port
        block.call(nil)
        return
      end

      begin
        @native_port = `chrome.runtime.connectNative(#{NATIVE_HOST_NAME})`

        `#{@native_port}.onMessage.addListener((msg) => {
          #{handle_native_message(`msg`)}
        })`

        `#{@native_port}.onDisconnect.addListener(() => {
          #{handle_native_disconnect}
        })`

        # Small delay to ensure connection is established
        `setTimeout(() => { #{block.call(nil)} }, 50)`
      rescue => e
        block.call("Failed to connect to native host: #{e.message}")
      end
    end

    def send_to_native(message, send_response)
      return unless @native_port

      request_id = message[:requestId] || `message.requestId`
      @pending_requests[request_id] = send_response

      `#{@native_port}.postMessage(#{message.to_n})`

      # Set timeout
      `setTimeout(() => {
        #{handle_request_timeout(request_id)}
      }, #{Messaging::DEFAULT_TIMEOUT})`
    end

    def handle_native_message(message)
      request_id = message[:requestId] || `message.requestId` || message[:request_id]
      send_response = @pending_requests.delete(request_id)

      return unless send_response

      # Forward response to content script
      `sendResponse(#{message.to_n})`
    end

    def handle_native_disconnect
      error = `chrome.runtime.lastError?.message || 'Native host disconnected'`

      @pending_requests.each do |request_id, send_response|
        send_error(send_response, request_id, Messaging::ErrorCodes::NATIVE_HOST_NOT_FOUND, error)
      end

      @pending_requests.clear
      @native_port = nil

      # Cancel current signing request if any
      cancel_current_signing
    end

    def handle_request_timeout(request_id)
      send_response = @pending_requests.delete(request_id)
      return unless send_response

      send_error(send_response, request_id, Messaging::ErrorCodes::TIMEOUT, "Operation timed out")
    end

    def send_error(send_response, request_id, code, message)
      response = Messaging.create_error(request_id, code, message)
      `sendResponse(#{response.to_n})`
    end

    def origin_allowed?(origin)
      # TODO: Make this configurable via extension options
      # For now, allow localhost and https origins
      return true if origin =~ /^https?:\/\/localhost/
      return true if origin =~ /^https:\/\//

      false
    end
  end
end

# Initialize background service worker
EasySign::Background.new
