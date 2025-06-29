# frozen_string_literal: true

require "starry"
require "openssl"
require "rack"
require "uri"
require "stringio"
require "net/http"

require_relative "linzer/version"
require_relative "linzer/common"
require_relative "linzer/helper"
require_relative "linzer/options"
require_relative "linzer/message"
require_relative "linzer/message/adapter"
require_relative "linzer/message/wrapper"
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

module Linzer
  class Error < StandardError; end

  class VerifyError < Error; end

  class SigningError < Error; end

  class << self
    include Key::Helper
    include Helper

    def verify(pubkey, message, signature, no_older_than: nil)
      Linzer::Verifier.verify(pubkey, message, signature, no_older_than: no_older_than)
    end

    def sign(key, message, components, options = {})
      Linzer::Signer.sign(key, message, components, options)
    end

    def signature_base(message, components, parameters)
      Linzer::Common.signature_base(message, components, parameters)
    end
  end

  FieldId = Message::Field::Identifier
end

require_relative "rack/auth/signature"
