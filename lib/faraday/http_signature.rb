# frozen_string_literal: true

require "faraday"
require_relative "http_signature/middleware"

module Faraday
  # Faraday middleware for signing and verifying HTTP messages
  # as defined in RFC 9421.
  #
  # Three registration points are provided so the middleware can be added
  # via +request+, +response+ or +use+, each with appropriate defaults:
  #
  # @example Sign outgoing requests
  #   conn = Faraday.new(url: "https://example.com") do |f|
  #     f.request :http_signature, key: my_key, components: %w[@method @path]
  #   end
  #
  # @example Verify incoming responses
  #   conn = Faraday.new(url: "https://example.com") do |f|
  #     f.response :http_signature, verify_key: server_pubkey
  #   end
  #
  # @example Sign requests and verify responses
  #   conn = Faraday.new(url: "https://example.com") do |f|
  #     f.use :http_signature, sign_key: my_key, verify_key: server_pubkey,
  #       verify_response: true, components: %w[@method @path]
  #   end
  #
  # @see Faraday::HttpSignature::Middleware
  # @see https://datatracker.ietf.org/doc/html/rfc9421 RFC 9421 - HTTP Message Signatures
  module HttpSignature
    Faraday::Request.register_middleware(http_signature:    Faraday::HttpSignature::Middleware::Request)
    Faraday::Response.register_middleware(http_signature:   Faraday::HttpSignature::Middleware::Response)
    Faraday::Middleware.register_middleware(http_signature: Faraday::HttpSignature::Middleware)
  end
end
