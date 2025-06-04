# frozen_string_literal: true

module Linzer
  class Key
    def initialize(material, params = {})
      @material = material
      @params   = Hash(params).clone.freeze
      validate
      freeze
    end

    attr_reader :material

    def key_id
      @params[:id]
    end

    def sign(*args)
      abstract_error = "Cannot sign data, \"#{self.class}\" is an abstract class."
      raise Error, abstract_error
    end

    def verify(*args)
      abstract_error = "Cannot verify signature, \"#{self.class}\" is an abstract class."
      raise Error, abstract_error
    end

    private

    def validate
      !material.nil? or raise Error.new "Invalid key. No key material provided."
    end

    def validate_digest
      no_digest = !@params.key?(:digest) || @params[:digest].nil? || String(@params[:digest]).empty?
      no_digest_error = "Invalid key definition, no digest algorithm was selected."
      raise Error, no_digest_error if no_digest
    end
  end
end
