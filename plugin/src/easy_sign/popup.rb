# frozen_string_literal: true
# backtick_javascript: true

require "native"
require "easy_sign/messaging"

# Popup controller for PIN entry
module EasySign
  class Popup
    def initialize
      @port = nil
      @signing_context = nil
      setup_ui
      connect_to_background
    end

    def setup_ui
      # Wait for DOM to be ready
      `document.addEventListener('DOMContentLoaded', () => {
        #{init_ui}
      })`
    end

    def init_ui
      # Get UI elements
      @pin_input = `document.getElementById('pin-input')`
      @submit_btn = `document.getElementById('submit-btn')`
      @cancel_btn = `document.getElementById('cancel-btn')`
      @status_text = `document.getElementById('status-text')`
      @origin_text = `document.getElementById('origin-text')`
      @error_text = `document.getElementById('error-text')`

      setup_event_listeners
      focus_pin_input
    end

    def setup_event_listeners
      # Submit button click
      `#{@submit_btn}.addEventListener('click', () => {
        #{submit_pin}
      })`

      # Cancel button click
      `#{@cancel_btn}.addEventListener('click', () => {
        #{cancel_signing}
      })`

      # Enter key in PIN input
      `#{@pin_input}.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          #{submit_pin}
        }
      })`

      # Clear error on input
      `#{@pin_input}.addEventListener('input', () => {
        #{clear_error}
      })`
    end

    def connect_to_background
      @port = `chrome.runtime.connect({ name: 'popup' })`

      `#{@port}.onMessage.addListener((message) => {
        #{handle_background_message(`message`)}
      })`

      `#{@port}.onDisconnect.addListener(() => {
        #{handle_disconnect}
      })`

      # Notify background that popup is ready
      send_to_background({ type: Messaging::Types::POPUP_READY })
    end

    def handle_background_message(message)
      type = message[:type] || `message.type`

      case type
      when "signing_context"
        handle_signing_context(message)
      when "error"
        show_error(message[:error] || `message.error`)
      when "pin_incorrect"
        show_error("Incorrect PIN. Please try again.")
        clear_pin
        focus_pin_input
      end
    end

    def handle_signing_context(context)
      @signing_context = context
      origin = context[:origin] || `context.origin`
      options = context[:options] || `context.options` || {}

      # Update UI with signing context
      if origin && @origin_text
        `#{@origin_text}.textContent = #{origin}`
      end

      # Show what will be signed
      if options[:reason] && @status_text
        `#{@status_text}.textContent = 'Reason: ' + #{options[:reason]}`
      end
    end

    def handle_disconnect
      # Background disconnected, close popup
      `window.close()`
    end

    def submit_pin
      pin = `#{@pin_input}.value`

      # Validate PIN
      if pin.nil? || `#{pin}.length === 0`
        show_error("Please enter your PIN")
        return
      end

      if `#{pin}.length < 4`
        show_error("PIN must be at least 4 characters")
        return
      end

      # Disable UI while processing
      disable_ui
      show_status("Signing document...")

      # Send PIN to background
      send_to_background({
        type: Messaging::Types::PIN_SUBMITTED,
        pin: pin
      })

      # Clear PIN from memory
      clear_pin
    end

    def cancel_signing
      send_to_background({ type: Messaging::Types::PIN_CANCELLED })
      `window.close()`
    end

    def send_to_background(message)
      return unless @port

      `#{@port}.postMessage(#{message.to_n})`
    end

    def show_error(message)
      return unless @error_text

      `#{@error_text}.textContent = #{message}`
      `#{@error_text}.style.display = 'block'`
      enable_ui
    end

    def clear_error
      return unless @error_text

      `#{@error_text}.textContent = ''`
      `#{@error_text}.style.display = 'none'`
    end

    def show_status(message)
      return unless @status_text

      `#{@status_text}.textContent = #{message}`
    end

    def clear_pin
      return unless @pin_input

      `#{@pin_input}.value = ''`
    end

    def focus_pin_input
      return unless @pin_input

      `#{@pin_input}.focus()`
    end

    def disable_ui
      `#{@pin_input}.disabled = true` if @pin_input
      `#{@submit_btn}.disabled = true` if @submit_btn
      `#{@cancel_btn}.disabled = true` if @cancel_btn
    end

    def enable_ui
      `#{@pin_input}.disabled = false` if @pin_input
      `#{@submit_btn}.disabled = false` if @submit_btn
      `#{@cancel_btn}.disabled = false` if @cancel_btn
      focus_pin_input
    end
  end
end

# Initialize popup
EasySign::Popup.new
