# frozen_string_literal: true

require_relative "bootstrap"

module Linzer
  module HTTP
    class << self
      # Registers the HTTP gem request adapter.
      # @api private
      def register_adapter
        request_class = ::HTTP::Request
        adapter_class = Linzer::Message::Adapter::HTTPGem::Request
        Linzer::Message.register_adapter(request_class, adapter_class)
      end
    end

    Bootstrap.load_dependencies
    register_adapter

    # HTTP.rb gem feature for automatic request signing.
    #
    # This feature integrates with the http.rb gem to automatically sign
    # outgoing HTTP requests. It wraps each request before sending and
    # adds the `signature` and `signature-input` headers.
    #
    # @note This file must be explicitly required:
    #   `require "linzer/http/signature_feature"`
    #
    # @example Basic usage
    #   require "linzer/http/signature_feature"
    #
    #   key = Linzer.generate_ed25519_key("my-key")
    #   response = HTTP
    #     .use(http_signature: { key: key })
    #     .get("https://example.com/api")
    #
    # @example With custom components and parameters
    #   response = HTTP
    #     .use(http_signature: {
    #       key: key,
    #       covered_components: %w[@method @authority @path date],
    #       params: { nonce: SecureRandom.hex(16) }
    #     })
    #     .post("https://example.com/api", json: { data: "value" })
    #
    # @see https://github.com/httprb/http http.rb gem
    class SignatureFeature < ::HTTP::Feature
      # Creates a new signature feature.
      #
      # @param key [Linzer::Key] The signing key (required)
      # @param params [Hash] Additional signature parameters
      #   (created, nonce, tag, etc.)
      # @param covered_components [Array<String>] Components to include
      #   in the signature. Defaults to `@method`, `@request-target`,
      #   `@authority`, and `date`.
      #
      # @raise [HTTP::Error] If key is nil or invalid
      def initialize(key:, params: {}, covered_components: default_components)
        @fields = Array(covered_components)
        @key    = validate_key(key)
        @params = Hash(params)
      end

      # @return [Array<String>] The components to include in signatures
      attr_reader :fields

      # @return [Hash] Additional signature parameters
      attr_reader :params

      # Wraps an outgoing request to add signature headers.
      #
      # Called automatically by http.rb for each request.
      #
      # @param request [HTTP::Request] The outgoing request
      # @return [HTTP::Request] The request with signature headers added
      def wrap_request(request)
        message   = Linzer::Message.new(request)
        signature = Linzer.sign(key, message, fields, **params)
        request.headers.merge!(signature.to_h)
        request
      end

      # Returns the default covered components.
      # @return [Array<String>] Default components from {Options::DEFAULT}
      def default_covered_components
        Linzer::Options::DEFAULT[:covered_components]
      end

      alias_method :default_components, :default_covered_components

      private

      attr_reader :key

      def validate_key(key)
        raise ::HTTP::Error, "Key can not be nil!"    if !key
        raise ::HTTP::Error, "Key object is invalid!" if !key.respond_to?(:sign)
        key
      end

      # Register this feature with http.rb
      ::HTTP::Options.register_feature(:http_signature, self)
    end
  end
end
