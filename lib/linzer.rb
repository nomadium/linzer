# frozen_string_literal: true

require "starry"
require "openssl"

require_relative "linzer/version"
require_relative "linzer/message"
require_relative "linzer/signature"
require_relative "linzer/signer"
require_relative "linzer/verifier"

module Linzer
  class Error < StandardError; end

  Key = Struct.new("Key", :material, :key_id, keyword_init: true) do |clazz|
    def sign(*args)
      # XXX: probably this is going to grow in complexity and will need
      # to be moved to its own class or dispatch to the signer
      !material.nil? or raise Error.new "Cannot sign data, key material cannot be null."
      material.sign(*args)
    end
  end

  class << self
    def verify(pubkey, message, signature)
      Linzer::Verifier.verify(pubkey, message, signature)
    end

    def sign(key, message, components, options = {})
      Linzer::Signer.sign(key, message, components, options)
    end
  end
end
