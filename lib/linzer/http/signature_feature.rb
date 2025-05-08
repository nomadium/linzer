# frozen_string_literal: true

require "linzer"

begin
  require "http"
  require_relative "../message/adapter/http_gem/request"
rescue LoadError # http gem is not a linzer core dependency
  # :nocov:
  puts "http gem is required to be installed to use this feature."
  false
  # :nocov:
else
  module Linzer
    module HTTP
      class << self
        def register_adapter
          request_class = ::HTTP::Request
          adapter_class = Linzer::Message::Adapter::HTTPGem::Request
          Linzer::Message.register_adapter(request_class, adapter_class)
        end
      end

      register_adapter

      class SignatureFeature < ::HTTP::Feature
        def initialize(key:, params: {}, covered_components: default_components)
          @fields = Array(covered_components)
          @key    = validate_key(key)
          @params = Hash(params)
        end

        attr_reader :fields, :params

        def wrap_request(request)
          message   = Linzer::Message.new(request)
          signature = Linzer.sign(key, message, fields, **params)
          request.headers.merge!(signature.to_h)
          request
        end

        def default_covered_components
          # Linzer::Options.DEFAULT_OPTIONS[:covered_components]
          %w[@method @request-target @authority date]
        end

        alias_method :default_components, :default_covered_components

        private

        attr_reader :key

        def validate_key(key)
          raise ::HTTP::Error, "Key can not be nil!"    if !key
          raise ::HTTP::Error, "Key object is invalid!" if !key.respond_to?(:sign)
          key
        end

        ::HTTP::Options.register_feature(:http_signature, self)
      end
    end
  end
end
