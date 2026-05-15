# frozen_string_literal: true

module Linzer
  # Convenience methods for signing and verifying HTTP messages.
  #
  # These methods provide a simpler interface for common use cases,
  # handling message wrapping and signature attachment automatically.
  #
  # @note These methods are mixed into the {Linzer} module and can be
  #   called directly as `Linzer.sign!` and `Linzer.verify!`.
  module Helper
    # Signs an HTTP request or response and attaches the signature.
    #
    # This is a convenience method that wraps the message, creates a signature,
    # and attaches it to the original HTTP message in one step.
    #
    # @param request_or_response [Net::HTTPRequest, Net::HTTPResponse, Rack::Request,
    #   Rack::Response, HTTP::Request] The HTTP message to sign
    # @param args [Hash] Keyword arguments
    # @option args [Linzer::Key] :key The private key to sign with (required)
    # @option args [Array<String>] :components The components to include in the
    #   signature (required). Example: `%w[@method @path content-type]`
    # @option args [String] :label Optional signature label (defaults to "sig1")
    # @option args [Hash] :params Additional signature parameters (created, nonce, etc.)
    #
    # @return [Object] The original HTTP message with signature headers attached
    #
    # @raise [SigningError] If signing fails
    # @raise [KeyError] If required arguments are missing
    #
    # @example Sign a Net::HTTP request
    #   request = Net::HTTP::Post.new(uri)
    #   request["content-type"] = "application/json"
    #   request["date"] = Time.now.httpdate
    #
    #   Linzer.sign!(request,
    #     key: private_key,
    #     components: %w[@method @path content-type date]
    #   )
    #   # request now has "signature" and "signature-input" headers
    #
    # @example Sign with additional parameters
    #   Linzer.sign!(request,
    #     key: private_key,
    #     components: %w[@method @path],
    #     label: "my-sig",
    #     params: { nonce: SecureRandom.hex(16), tag: "my-app" }
    #   )
    def sign!(request_or_response, key:, components:, label: nil, params: {}, profile: nil)
      message = Message.new(request_or_response)
      resolved_profile = Signing::Profile.resolve(profile)

      # XXX:
      # if Message.build were available, there would not be a need to mutate message with set_header!
      # however, it would require this ugly special case shown in the comment below:
      # is there a better way to do this?
      #
      # if resolved_profile != :web_bot_auth || !resolved_profile.agent
      #   message = Message.new(request_or_response)
      # else
      #   message = Message.build(request_or_response, additional_headers: {"signature-agent" => agent})
      #   raise Error unless message.request?
      # end

      ctx = Signing::Context.new(
        message:    message,
        key:        key,
        label:      label,
        components: Array(components),
        params:     Hash(params)
      )

      resolved_profile&.apply(ctx)

      signature = Linzer::Signer.sign(
        ctx.key,
        ctx.message,
        ctx.components,
        ctx.params
      )

      message.attach!(signature)
    end

    # Verifies a signed HTTP request or response.
    #
    # Extracts the signature from the message headers, rebuilds the signature
    # base, and verifies the cryptographic signature.
    #
    # @param request_or_response [Net::HTTPRequest, Net::HTTPResponse, Rack::Request,
    #   Rack::Response, HTTP::Request, HTTP::Response] The signed HTTP message
    # @param key [Linzer::Key, nil] The public key to verify with. If nil,
    #   a block must be provided to look up the key.
    # @param no_older_than [Integer] Maximum signature age in seconds.
    #   Defaults to 900 (15 minutes). Set to nil to disable age checking.
    #
    # @yield [keyid] Block to look up the verification key by keyid.
    #   Only called if `key` is nil.
    # @yieldparam keyid [String] The key identifier from the signature
    # @yieldreturn [Linzer::Key] The public key to use for verification
    #
    # @return [true] Returns true if verification succeeds
    #
    # @raise [VerifyError] If verification fails
    # @raise [Error] If no key is provided and no keyid is in the signature
    #
    # @example Verify with a known key
    #   Linzer.verify!(request, key: public_key)
    #
    # @example Verify with key lookup
    #   Linzer.verify!(request) do |keyid|
    #     PublicKey.find_by(identifier: keyid).to_linzer_key
    #   end
    #
    # @example Verify with custom age limit (5 minutes)
    #   Linzer.verify!(request, key: public_key, no_older_than: 300)
    #
    # @example Verify without age checking
    #   Linzer.verify!(request, key: public_key, no_older_than: nil)
    def verify!(request_or_response, key: nil, no_older_than: 900)
      message = Message.new(request_or_response)
      signature_headers = {}
      %w[signature-input signature].each do |name|
        value = message.header(name)
        signature_headers[name] = value if value
      end
      signature = Signature.build(signature_headers)
      keyid = signature.parameters["keyid"]
      raise Linzer::Error, "key not found" if !key && !keyid
      verify_key = block_given? ? (yield keyid) : key
      Linzer.verify(verify_key, message, signature, no_older_than: no_older_than)
    end
  end
end
