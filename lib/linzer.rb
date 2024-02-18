# frozen_string_literal: true

require "starry"
require "openssl"

require_relative "linzer/version"
require_relative "linzer/message"
require_relative "linzer/verifier"

module Linzer
  class Error < StandardError; end

  class << self
    def verify(pubkeys, message)
      Linzer::Verifier.new(pubkeys)
        .verify(message)
    end
  end
end
