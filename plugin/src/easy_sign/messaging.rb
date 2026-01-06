# frozen_string_literal: true
# backtick_javascript: true

# Message protocol constants and helpers for EasySign browser extension
module EasySign
  module Messaging
    # Message types
    module Types
      # Requests from page/content script to background
      SIGN_REQUEST = "sign_request"
      VERIFY_REQUEST = "verify_request"
      AVAILABILITY_REQUEST = "availability_request"
      CANCEL_REQUEST = "cancel_request"

      # Responses from background to page/content script
      SIGN_RESPONSE = "sign_response"
      VERIFY_RESPONSE = "verify_response"
      AVAILABILITY_RESPONSE = "availability_response"
      ERROR_RESPONSE = "error"

      # Internal extension messages
      PIN_SUBMITTED = "pin_submitted"
      PIN_CANCELLED = "pin_cancelled"
      POPUP_READY = "popup_ready"
    end

    # Error codes matching native host protocol
    module ErrorCodes
      TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND"
      PIN_INCORRECT = "PIN_INCORRECT"
      TOKEN_LOCKED = "TOKEN_LOCKED"
      INVALID_PDF = "INVALID_PDF"
      SIGNING_FAILED = "SIGNING_FAILED"
      VERIFICATION_FAILED = "VERIFICATION_FAILED"
      NATIVE_HOST_NOT_FOUND = "NATIVE_HOST_NOT_FOUND"
      TIMEOUT = "TIMEOUT"
      CANCELLED = "CANCELLED"
      ORIGIN_NOT_ALLOWED = "ORIGIN_NOT_ALLOWED"
      INTERNAL_ERROR = "INTERNAL_ERROR"
    end

    # Message targets for postMessage routing
    module Targets
      EXTENSION = "easy-sign-extension"
      PAGE = "easy-sign-page"
    end

    # Default timeout for signing operations (ms)
    DEFAULT_TIMEOUT = 120_000 # 2 minutes

    # Generate unique request ID
    def self.generate_request_id
      # Use crypto.randomUUID if available, fallback to timestamp + random
      `typeof crypto !== 'undefined' && crypto.randomUUID ?
        crypto.randomUUID() :
        Date.now().toString(36) + Math.random().toString(36).substr(2)`
    end

    # Create a request message
    def self.create_request(type, payload = {})
      {
        type: type,
        request_id: generate_request_id,
        payload: payload,
        timestamp: `Date.now()`
      }
    end

    # Create a response message
    def self.create_response(request_id, type, payload = nil, error = nil)
      {
        type: type,
        request_id: request_id,
        payload: payload,
        error: error,
        timestamp: `Date.now()`
      }
    end

    # Create an error response
    def self.create_error(request_id, code, message, details = nil)
      create_response(
        request_id,
        Types::ERROR_RESPONSE,
        nil,
        { code: code, message: message, details: details }
      )
    end

    # Human-readable error messages
    ERROR_MESSAGES = {
      ErrorCodes::TOKEN_NOT_FOUND => "Hardware token not found. Please connect your token.",
      ErrorCodes::PIN_INCORRECT => "Incorrect PIN entered.",
      ErrorCodes::TOKEN_LOCKED => "Token is locked. Please contact your administrator.",
      ErrorCodes::INVALID_PDF => "The PDF file is invalid or corrupted.",
      ErrorCodes::SIGNING_FAILED => "Failed to sign the document.",
      ErrorCodes::VERIFICATION_FAILED => "Failed to verify the signature.",
      ErrorCodes::NATIVE_HOST_NOT_FOUND => "EasySign native host not installed.",
      ErrorCodes::TIMEOUT => "Operation timed out.",
      ErrorCodes::CANCELLED => "Operation was cancelled.",
      ErrorCodes::ORIGIN_NOT_ALLOWED => "This website is not allowed to use EasySign.",
      ErrorCodes::INTERNAL_ERROR => "An internal error occurred."
    }.freeze

    def self.error_message(code)
      ERROR_MESSAGES[code] || "Unknown error: #{code}"
    end
  end
end
