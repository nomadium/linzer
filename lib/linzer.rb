# frozen_string_literal: true

require "starry"
require "openssl"
require "rack"
require "uri"
require "stringio"
require "net/http"

require_relative "linzer/version"
require_relative "linzer/common"
require_relative "linzer/options"
require_relative "linzer/message"
require_relative "linzer/message/adapter"
require_relative "linzer/message/wrapper"
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
require_relative "rack/auth/signature"

module Linzer
  class Error < StandardError; end

  class VerifyError < Error; end

  class SigningError < Error; end

  class << self
    include Key::Helper

    def verify(pubkey, message, signature, no_older_than: nil)
      Linzer::Verifier.verify(pubkey, message, signature, no_older_than: no_older_than)
    end

    def sign(key, message, components, options = {})
      Linzer::Signer.sign(key, message, components, options)
    end

    def sign!(request_or_response, **args)
      message = Message.new(request_or_response)
      options = {}

      label = args[:label]
      options[:label] = label if label
      options.merge!(args.fetch(:params, {}))

      key = args.fetch(:key)
      signature = Linzer::Signer.sign(key, message, args.fetch(:components), options)
      message.attach!(signature)
    end

    def verify!(request_or_response, key: nil, no_older_than: 900)
      message = Message.new(request_or_response)
      signature_headers = {}
      %w(signature-input signature).each do |name|
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
