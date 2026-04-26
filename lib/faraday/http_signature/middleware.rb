# frozen_string_literal: true

module Faraday
  module HttpSignature
    # Raised when HTTP signature verification fails.
    #
    # Inherits from {Faraday::Error} so that standard Faraday error handling
    # (e.g. +rescue Faraday::Error+) catches verification failures.
    #
    # @example Catching a verification failure
    #   begin
    #     response = conn.get("/")
    #   rescue Faraday::HttpSignature::VerifyError => e
    #     e.message            # => "Failed to verify message: Invalid signature."
    #     e.response           # => the Faraday response
    #     e.wrapped_exception  # => the original Linzer::VerifyError
    #   end
    class VerifyError < Faraday::Error; end

    class SigningError < Faraday::Error; end

    # Faraday middleware for HTTP message signing and verification (RFC 9421).
    #
    # When registered via +request+, signs outgoing requests (default).
    # When registered via +response+, verifies incoming response signatures.
    # When registered via +use+, signs requests by default; pass
    # +verify_response: true+ to also verify responses.
    #
    # == Verification result metadata
    #
    # After response verification, the middleware stores results in
    # +env[:http_signature_verified]+ (+true+ or +false+) and
    # +env[:http_signature]+ (the {Linzer::Signature} on success).
    # These are accessible via +response.env[:http_signature_verified]+.
    #
    # @example Sign requests
    #   conn = Faraday.new(url: "https://example.com") do |f|
    #     f.request :http_signature, key: my_key, components: %w[@method @path]
    #   end
    #
    # @example Verify responses
    #   conn = Faraday.new(url: "https://example.com") do |f|
    #     f.response :http_signature, verify_key: server_pubkey
    #   end
    #
    # @example Lenient verification (no exception on failure)
    #   conn = Faraday.new(url: "https://example.com") do |f|
    #     f.response :http_signature, verify_key: server_pubkey, strict: false
    #   end
    #   response = conn.get("/")
    #   response.env[:http_signature_verified]  # => true or false
    #
    # @see https://datatracker.ietf.org/doc/html/rfc9421 RFC 9421
    class Middleware < Faraday::Middleware
      DEFAULT_OPTIONS = {
        sign_request:    true,
        verify_response: false,
        strict:          true
      }.freeze

      class Options < Faraday::Options.new(:key, :sign_request, :sign_key, :components, :verify_response, :verify_key, :params, :strict)
        def key
          self[:key]
        end

        def sign_request?
          self[:sign_request] != false
        end

        def verify_response?
          self[:verify_response]
        end

        def strict?
          self[:strict] != false
        end

        def components
          Array(self[:components])
        end

        def params
          Hash(self[:params])
        end
      end

      def initialize(app, options = nil)
        super(app)
        defaults = self.class::DEFAULT_OPTIONS
        merged = defaults.merge(Hash(options))
        @options = Options.from(merged)
      end

      def on_request(env)
        return unless options.sign_request?

        key = resolve_signing_key
        request = Linzer::Faraday::Utils.create_request(env)
        message = Linzer::Message.new(request)

        signature = Linzer.sign(key, message, options.components, options.params)
        env.request_headers.merge!(signature.to_h)
        env
      rescue Linzer::Error => e
        raise SigningError, e if options.strict?
      end

      def on_complete(env)
        env[:http_signature_verified] = false
        return unless options.verify_response?

        key = resolve_verify_key
        response = ::Faraday::Response.new(env)
        message = Linzer::Message.new(response)
        signature = Linzer::Signature.build(response.headers)

        Linzer.verify(key, message, signature)
        env[:http_signature_verified] = true
        env[:http_signature] = signature
        env
      rescue Linzer::Error => e
        raise VerifyError.new(e, response: response) if options.strict?
      end

      private

      def resolve_signing_key
        key = options.sign_key
        key ||= options.key unless options.sign_request? && options.verify_response?
        raise Linzer::Error, "No signing key provided!" if !key
        raise Linzer::Error, "Invalid key!" if !key.is_a?(Linzer::Key)

        key
      end

      def resolve_verify_key
        key = options.verify_key
        key ||= options.key unless options.sign_request? && options.verify_response?
        raise Linzer::Error, "No verification key provided!" if !key
        raise Linzer::Error, "Invalid key!" if !key.is_a?(Linzer::Key)

        key
      end

      class Request < self
      end

      class Response < self
        DEFAULT_OPTIONS = {
          sign_request:    false,
          verify_response: true,
          strict:          true
        }.freeze
      end
    end
  end
end
