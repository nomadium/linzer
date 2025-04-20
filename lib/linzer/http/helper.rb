# frozen_string_literal: true

require "net/http"

module Linzer
  module HTTP
    module Helper
      def request(verb, uri, options = {})
        key = options[:key]
        validate_key(key)

        req_uri = URI(uri)
        http = Net::HTTP.new(req_uri.host, req_uri.port)
        # http.set_debug_output($stderr) if options[:debug]
        http.set_debug_output($stderr)

        headers   = options[:headers] || {}
        request   = build_request(verb, uri, headers)
        message   = Linzer::Message.new(request)
        covered_components = options[:covered_components] || default_components
        params = options[:params] || {}
        signature = Linzer.sign(key, message, covered_components, **params)

        case verb
        when :get, :head, :options, :trace, :delete
          # method = %i[get head].include?(verb) ? "request_#{verb}".to_sym : verb
          http.public_send(verb, uri, headers.merge(signature.to_h))
        when :post, :put, :patch
          data = options[:data] || "" if %i[post put patch].include?(verb)
          # method = %i[post put].include?(verb) ? "request_#{verb}".to_sym : verb
          http.public_send(verb, uri, data, headers.merge(signature.to_h))
        else
          raise Linzer::Error, "Unknown/unsupported HTTP method: #{verb.to_s}"
        end
      end

      def self.known_http_methods
        Net::HTTP
          .constants
          .map    { |const| Net::HTTP.const_get(const) }
          .select { |klass| klass.is_a?(Class) && klass.const_defined?(:METHOD) }
          .map    { |klass| klass::METHOD }
      end

      known_http_methods.each do |http_method|
        method = http_method.downcase.to_sym
        define_method(method) do |uri, options|
          options ||= {}
          request method, uri, options
        end
      end

      def default_covered_components
        # Linzer::Options.DEFAULT_OPTIONS[:covered_components]
        %w[@method @request-target @authority date]
      end

      alias_method :default_components, :default_covered_components

      def validate_key(key)
        raise Linzer::Error, "Key can not be nil!"    if !key
        raise Linzer::Error, "Key object is invalid!" if !key.respond_to?(:sign)
        key
      end

      def build_request(method, uri, headers)
        request_method = String(method).upcase
        env = Rack::MockRequest.env_for(uri, "REQUEST_METHOD" => request_method)
        request = Rack::Request.new(env)

        headers.each do |h, v|
          request.set_header Linzer::Request.rack_header_name(h), v
        end

        request
      end
    end
  end
end
