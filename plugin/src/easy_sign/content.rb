# frozen_string_literal: true
# backtick_javascript: true

require "native"
require "easy_sign/messaging"

# Content script for EasySign browser extension
# Bridges communication between web page and extension background
module EasySign
  class ContentScript
    def initialize
      @pending_responses = {}
      setup_page_listener
      inject_api_script
      puts "EasySign content script initialized"
    end

    def setup_page_listener
      # Listen for messages from the page (inject.js)
      `window.addEventListener('message', (event) => {
        // Only accept messages from the same window
        if (event.source !== window) return;

        // Only accept messages targeted at the extension
        if (!event.data || event.data.target !== #{Messaging::Targets::EXTENSION.to_n}) return;

        #{handle_page_message(`event.data`, `event.origin`)}
      })`
    end

    def handle_page_message(data, origin)
      request_id = data[:request_id] || `data.requestId` || `data.request_id`
      type = data[:type] || `data.type`

      # Forward to background script
      `chrome.runtime.sendMessage(#{data.to_n}, (response) => {
        #{handle_background_response(`response`, request_id)}
      })`
    end

    def handle_background_response(response, request_id)
      # Check for chrome runtime errors
      error = `chrome.runtime.lastError`
      if error
        response = Messaging.create_error(
          request_id,
          Messaging::ErrorCodes::INTERNAL_ERROR,
          `error.message || 'Extension error'`
        )
      end

      # Send response back to page
      post_to_page(response)
    end

    def post_to_page(message)
      page_message = (message || {}).merge(target: Messaging::Targets::PAGE)
      `window.postMessage(#{page_message.to_n}, '*')`
    end

    def inject_api_script
      # Inject the page-context script that exposes window.EasySign
      `const script = document.createElement('script');
       script.src = chrome.runtime.getURL('inject.js');
       script.onload = function() {
         this.remove();
       };
       (document.head || document.documentElement).appendChild(script);`
    end
  end
end

# Initialize content script
EasySign::ContentScript.new
