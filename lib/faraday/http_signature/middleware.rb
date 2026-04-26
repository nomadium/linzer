# frozen_string_literal: true

module Faraday
  module HttpSignature
    # Raised when HTTP response signature verification fails in strict mode.
    #
    # Inherits from {Faraday::Error} so that standard Faraday error handling
    # (e.g. +rescue Faraday::Error+) catches verification failures.
    # The original {Linzer::VerifyError} is preserved as {#wrapped_exception}
    # and the {Faraday::Response} is available via {#response}.
    #
    # @example Catching a verification failure
    #   begin
    #     response = conn.get("/")
    #   rescue Faraday::HttpSignature::VerifyError => e
    #     e.message            # => "Failed to verify message: Invalid signature."
    #     e.response           # => the Faraday::Response object
    #     e.wrapped_exception  # => the original Linzer::VerifyError
    #   end
    #
    # @see Middleware
    class VerifyError < Faraday::Error; end

    # Raised when HTTP request signature creation fails.
    #
    # Inherits from {Faraday::Error} so that standard Faraday error handling
    # (e.g. +rescue Faraday::Error+) catches verification failures.
    # The original {Linzer::Error} is preserved as {#wrapped_exception}.
    #
    # @example Catching a signing failure
    #   begin
    #     response = conn.post("/")
    #   rescue Faraday::HttpSignature::SigningError => e
    #     e.message            # => "Failed to sign message: Missing component."
    #     e.wrapped_exception  # => the original Linzer::Error
    #   end
    #
    # @see Middleware
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
      # Default options for the base middleware class (used by +use+
      # and +request+ registrations). Signs requests, does not verify
      # responses, strict mode enabled.
      DEFAULT_OPTIONS = {
        sign_request:    true,
        verify_response: false,
        strict:          true
      }.freeze

      # Configuration options for the HTTP signature middleware.
      #
      # @!attribute [rw] key
      #   @return [Linzer::Key, nil] generic key used for signing or
      #     verification when only one mode is active
      # @!attribute [rw] sign_request
      #   @return [Boolean] whether to sign outgoing requests
      #     (defaults to +true+)
      # @!attribute [rw] sign_key
      #   @return [Linzer::Key, nil] explicit key for signing; required
      #     when both signing and verification are enabled
      # @!attribute [rw] components
      #   @return [Array<String>] HTTP message components to include in
      #     the signature (e.g. +["@method", "@path", "content-type"]+)
      # @!attribute [rw] verify_response
      #   @return [Boolean] whether to verify incoming response signatures
      #     (defaults to +false+)
      # @!attribute [rw] verify_key
      #   @return [Linzer::Key, nil] explicit key for verification; required
      #     when both signing and verification are enabled
      # @!attribute [rw] params
      #   @return [Hash] additional signature parameters
      #     (e.g. +{ tag: "my_tag" }+)
      # @!attribute [rw] strict
      #   @return [Boolean] when +true+ (default), raises
      #     {VerifyError} on verification failure; when +false+,
      #     sets +env[:http_signature_verified]+ to +false+ and continues
      class Options < Faraday::Options.new(:key, :sign_request, :sign_key, :components, :verify_response, :verify_key, :params, :strict)
        # Returns the generic key.
        # @return [Linzer::Key, nil]
        def key
          self[:key]
        end

        # Whether outgoing requests should be signed.
        # Defaults to +true+ (returns +true+ when unset).
        # @return [Boolean]
        def sign_request?
          self[:sign_request] != false
        end

        # Whether incoming responses should be verified.
        # Defaults to +false+ (returns +false+ when unset).
        # @return [Boolean]
        def verify_response?
          self[:verify_response]
        end

        # Whether verification failures should raise an exception.
        # Defaults to +true+ (returns +true+ when unset).
        # @return [Boolean]
        def strict?
          self[:strict] != false
        end

        # Returns the list of HTTP message components to sign.
        # @return [Array<String>]
        def components
          Array(self[:components])
        end

        # Returns additional signature parameters.
        # @return [Hash]
        def params
          Hash(self[:params])
        end
      end

      # Creates a new middleware instance.
      #
      # Merges class-level {DEFAULT_OPTIONS} with the user-provided options
      # so that subclasses ({Request}, {Response}) can override defaults.
      #
      # @param app [#call] the next middleware or adapter in the stack
      # @param options [Hash, nil] middleware options
      # @option options [Linzer::Key] :key generic key for signing or verification
      # @option options [Linzer::Key] :sign_key explicit signing key
      # @option options [Linzer::Key] :verify_key explicit verification key
      # @option options [Array<String>] :components components to sign
      # @option options [Hash] :params additional signature parameters
      # @option options [Boolean] :sign_request (+true+) whether to sign requests
      # @option options [Boolean] :verify_response (+false+) whether to verify responses
      # @option options [Boolean] :strict (+true+) raise on verification failure
      def initialize(app, options = nil)
        super(app)
        defaults = self.class::DEFAULT_OPTIONS
        merged = defaults.merge(Hash(options))
        @options = Options.from(merged)
      end

      # Signs the outgoing request when {Options#sign_request?} is +true+.
      #
      # Resolves the signing key, builds a {Linzer::Message} from the
      # Faraday environment, generates a signature over the configured
      # components, and merges the +signature+ and +signature-input+
      # headers into the request.
      #
      # @param env [Faraday::Env] the middleware environment
      # @return [Faraday::Env, nil] the modified env, or +nil+ if signing
      #   is disabled
      # @raise [Linzer::Error] if no valid signing key is available
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

      # Verifies the response signature when {Options#verify_response?} is +true+.
      #
      # On success, sets +env[:http_signature_verified]+ to +true+ and
      # +env[:http_signature]+ to the verified {Linzer::Signature}.
      #
      # On failure in strict mode (default), raises {VerifyError}.
      # In lenient mode (+strict: false+), sets
      # +env[:http_signature_verified]+ to +false+ and allows the response
      # to continue through the middleware stack.
      #
      # @param env [Faraday::Env] the middleware environment
      # @return [Faraday::Env, nil] the modified env, or +nil+ if verifying
      #   is disabled
      # @raise [VerifyError] if verification fails and +strict+ is +true+
      # @raise [Linzer::Error] if no valid verification key is available
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

      # Resolves the key to use for signing requests.
      #
      # Prefers {Options#sign_key}. Falls back to the generic {Options#key}
      # when only one mode (sign or verify) is active. When both modes are
      # active, the generic key is ambiguous and +sign_key+ must be set
      # explicitly.
      #
      # @return [Linzer::Key] the resolved signing key
      # @raise [Linzer::Error] if no key is available or the key is invalid
      def resolve_signing_key
        key = options.sign_key
        key ||= options.key unless options.sign_request? && options.verify_response?
        raise Linzer::Error, "No signing key provided!" if !key
        raise Linzer::Error, "Invalid key!" if !key.is_a?(Linzer::Key)

        key
      end

      # Resolves the key to use for verifying response signatures.
      #
      # Prefers {Options#verify_key}. Falls back to the generic {Options#key}
      # when only one mode (sign or verify) is active. When both modes are
      # active, the generic key is ambiguous and +verify_key+ must be set
      # explicitly.
      #
      # @return [Linzer::Key] the resolved verification key
      # @raise [Linzer::Error] if no key is available or the key is invalid
      def resolve_verify_key
        key = options.verify_key
        key ||= options.key unless options.sign_request? && options.verify_response?
        raise Linzer::Error, "No verification key provided!" if !key
        raise Linzer::Error, "Invalid key!" if !key.is_a?(Linzer::Key)

        key
      end

      # Subclass registered under {Faraday::Request}.
      #
      # Inherits the base {DEFAULT_OPTIONS} which sign requests by default
      # and do not verify responses.
      #
      # @example
      #   f.request :http_signature, key: my_key, components: %w[@method @path]
      class Request < self
      end

      # Subclass registered under {Faraday::Response}.
      #
      # Overrides {DEFAULT_OPTIONS} to verify responses by default and
      # not sign requests.
      #
      # @example
      #   f.response :http_signature, verify_key: server_pubkey
      class Response < self
        # Default options for the response subclass. Verifies responses
        # and does not sign requests.
        DEFAULT_OPTIONS = {
          sign_request:    false,
          verify_response: true,
          strict:          true
        }.freeze
      end
    end
  end
end
