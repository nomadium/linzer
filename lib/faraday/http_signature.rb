# frozen_string_literal: true

require "faraday"
require_relative "http_signature/middleware"

module Faraday
  # Faraday middleware for signing and verifying HTTP messages
  # as defined in RFC 9421.
  #
  # @example
  #   conn = Faraday.new(url: "https://example.com") do |f|
  #     f.request :http_signature, key: my_key, covered_components: %w[@method @path]
  #   end
  #
  # @see https://datatracker.ietf.org/doc/html/rfc9421 RFC 9421 - HTTP Message Signatures
  module HttpSignature
    Faraday::Request.register_middleware(http_signature:    Faraday::HttpSignature::Middleware::Request)
    Faraday::Response.register_middleware(http_signature:   Faraday::HttpSignature::Middleware::Response)
    Faraday::Middleware.register_middleware(http_signature: Faraday::HttpSignature::Middleware)
  end
end
