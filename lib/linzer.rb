# frozen_string_literal: true

require "starry"
require "openssl"
require "uri"
require "net/http"

require_relative "linzer/version"
require_relative "linzer/common"
require_relative "linzer/signature/context"
require_relative "linzer/signature/profile"
require_relative "linzer/helper"
require_relative "linzer/options"
require_relative "linzer/message"
require_relative "linzer/message/adapter"
require_relative "linzer/message/wrapper"
require_relative "linzer/message/overlay"
require_relative "linzer/message/field"
require_relative "linzer/message/field/parser"
require_relative "linzer/signature"
require_relative "linzer/key"
require_relative "linzer/rsa"
require_relative "linzer/rsa_pss"
require_relative "linzer/hmac"
require_relative "linzer/ed25519"
require_relative "linzer/ecdsa"
require_relative "linzer/key/helper"
require_relative "linzer/signer"
require_relative "linzer/verifier"
require_relative "linzer/http"
require_relative "linzer/http/structured_field"

# Linzer is a Ruby library for HTTP Message Signatures as defined in RFC 9421.
#
# It provides functionality to sign and verify HTTP messages using various
# cryptographic algorithms including RSA-PSS, HMAC-SHA256, ECDSA, and Ed25519.
#
# @example Signing a request with Ed25519
#   key = Linzer.generate_ed25519_key("my-key-id")
#   request = Net::HTTP::Post.new(URI("https://example.com/api"))
#   request["date"] = Time.now.httpdate
#
#   Linzer.sign!(request,
#     key: key,
#     components: %w[@method @request-target date]
#   )
#
# @example Verifying a signed request
#   pubkey = Linzer.new_ed25519_public_key(public_key_pem, "my-key-id")
#   Linzer.verify!(request, key: pubkey)
#
# @see https://www.rfc-editor.org/rfc/rfc9421.html RFC 9421 - HTTP Message Signatures
# @see https://github.com/nomadium Author on GitHub
# @author Miguel Landaeta
module Linzer
  # Base error class for all Linzer errors.
  # @see VerifyError
  # @see SigningError
  class Error < StandardError; end

  # Raised when signature verification fails.
  #
  # @example Handling verification errors
  #   begin
  #     Linzer.verify(pubkey, message, signature)
  #   rescue Linzer::VerifyError => e
  #     puts "Verification failed: #{e.message}"
  #   end
  class VerifyError < Error; end

  # Raised when message signing fails.
  #
  # @example Handling signing errors
  #   begin
  #     Linzer.sign(key, message, components)
  #   rescue Linzer::SigningError => e
  #     puts "Signing failed: #{e.message}"
  #   end
  class SigningError < Error; end

  class << self
    include Key::Helper
    include Helper

    # Verifies an HTTP message signature.
    #
    # @param pubkey [Linzer::Key] The public key to verify the signature with
    # @param message [Linzer::Message] The HTTP message to verify
    # @param signature [Linzer::Signature] The signature to verify
    # @param no_older_than [Integer, nil] Maximum age of signature in seconds.
    #   If provided, signatures with a `created` timestamp older than this
    #   value will be rejected to mitigate replay attacks.
    #
    # @return [true] Returns true if verification succeeds
    # @raise [VerifyError] If verification fails for any reason
    #
    # @example Basic verification
    #   Linzer.verify(pubkey, message, signature)
    #
    # @example Verification with age limit (reject signatures older than 5 minutes)
    #   Linzer.verify(pubkey, message, signature, no_older_than: 300)
    #
    # @see Linzer::Verifier.verify
    def verify(pubkey, message, signature, no_older_than: nil)
      Linzer::Verifier.verify(pubkey, message, signature, no_older_than: no_older_than)
    end

    # Signs an HTTP message.
    #
    # @param key [Linzer::Key] The private key to sign with
    # @param message [Linzer::Message] The HTTP message to sign
    # @param components [Array<String>] The message components to include in
    #   the signature (e.g., `["@method", "@path", "content-type"]`)
    # @param options [Hash] Additional signature parameters
    # @option options [Integer] :created Unix timestamp for signature creation
    #   (defaults to current time)
    # @option options [String] :keyid Key identifier to include in signature
    # @option options [String] :label Signature label (defaults to "sig1")
    # @option options [String] :nonce A unique nonce value
    # @option options [String] :tag Application-specific tag
    # @option options [Integer] :expires Unix timestamp for signature expiration
    #
    # @return [Linzer::Signature] The generated signature
    # @raise [SigningError] If signing fails
    #
    # @example Sign with default options
    #   signature = Linzer.sign(key, message, %w[@method @path date])
    #
    # @example Sign with custom parameters
    #   signature = Linzer.sign(key, message, %w[@method @path],
    #     keyid: "my-key",
    #     created: Time.now.to_i,
    #     nonce: SecureRandom.hex(16)
    #   )
    #
    # @see Linzer::Signer.sign
    def sign(key, message, components, options = {})
      Linzer::Signer.sign(key, message, components, options)
    end

    # Computes the signature base string for an HTTP message.
    #
    # The signature base is the canonical string representation that gets
    # signed. This method is primarily useful for debugging or implementing
    # custom signing logic.
    #
    # @param message [Linzer::Message] The HTTP message
    # @param components [Array<String>] Serialized component identifiers
    # @param parameters [Hash] Signature parameters
    #
    # @return [String] The signature base string
    #
    # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5 RFC 9421 Section 2.5
    def signature_base(message, components, parameters)
      Linzer::Common.signature_base(message, components, parameters)
    end
  end

  # Alias for {Message::Field::Identifier} for convenient access.
  # Used for serializing and deserializing component identifiers.
  FieldId = Message::Field::Identifier
end
