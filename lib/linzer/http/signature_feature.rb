# frozen_string_literal: true

require "linzer"

begin
  require "http"
rescue LoadError # http gem is not a linzer core dependency
  # :nocov:
  puts "http gem is required to be installed to use this feature."
  false
  # :nocov:
else
  module Linzer
    module HTTP
      class SignatureFeature < ::HTTP::Feature
        def initialize(key:, params: {}, covered_components: default_components)
          @fields = Array(covered_components)
          @key    = validate_key(key)
          @params = Hash(params)
        end

        attr_reader :fields, :params

        def wrap_request(request)
          message   = Linzer::Message.new(adapt_request(request))
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

        def adapt_request(request)
          env = Rack::MockRequest.env_for(request.uri)
          rack_request = Rack::Request.new(env)

          request.headers.each do |h, v|
            rack_request.set_header Linzer::Request.rack_header_name(h), v
          end

          rack_request
        end

        ::HTTP::Options.register_feature(:http_signature, self)
      end
    end
  end
end
