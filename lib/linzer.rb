# frozen_string_literal: true

require "starry"
require "openssl"

require_relative "linzer/version"
require_relative "linzer/common"
require_relative "linzer/message"
require_relative "linzer/signature"
require_relative "linzer/key"
require_relative "linzer/rsa"
require_relative "linzer/hmac"
require_relative "linzer/ed25519"
require_relative "linzer/ecdsa"
require_relative "linzer/key/helper"
require_relative "linzer/signer"
require_relative "linzer/verifier"

module Linzer
  class Error < StandardError; end

  class << self
    include Key::Helper

    def verify(pubkey, message, signature)
      Linzer::Verifier.verify(pubkey, message, signature)
    end

    def sign(key, message, components, options = {})
      Linzer::Signer.sign(key, message, components, options)
    end
  end
end
