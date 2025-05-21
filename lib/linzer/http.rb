# frozen_string_literal: true

require "net/http"

module Linzer
  module HTTP
    extend self

    def self.known_http_methods
      Net::HTTP
        .constants
        .map    { |const| Net::HTTP.const_get(const) }
        .select { |klass| klass.is_a?(Class) && klass.const_defined?(:METHOD) }
        .map    { |klass| klass::METHOD }
        .freeze
    end

    known_http_methods.each do |http_method|  # e.g.:
      method = http_method.downcase.to_sym    #
      define_method(method) do |uri, options| # def post(uri, **options)
        options ||= {}                        #   request :post, uri, options
        request method, uri, options          # end
      end
    end

    private

    def request(verb, uri, options = {})
      validate_verb(verb)

      key = options[:key]
      validate_key(key)

      req_uri = URI(uri)
      http = Net::HTTP.new(req_uri.host, req_uri.port)

      http.use_ssl = req_uri.scheme == "https"
      http.set_debug_output($stderr) if options[:debug]

      headers    = build_headers(options[:headers] || {})
      request    = build_request(verb, uri, headers)
      message    = Linzer::Message.new(request)
      components = options[:covered_components] || default_components
      params     = options[:params] || {}
      signature  = Linzer.sign(key, message, components, **params)

      do_request(http, uri, verb, options[:data], signature, headers)
    end

    def default_components
      Linzer::Options::DEFAULT[:covered_components]
    end

    def validate_verb(verb)
      method_name = verb.to_s.upcase
      if !known_http_methods.include?(method_name)
        raise Linzer::Error, "Unknown/unsupported HTTP method: '#{method_name}'"
      end
    end

    def validate_key(key)
      raise Linzer::Error, "Key can not be nil!"    if !key
      raise Linzer::Error, "Key object is invalid!" if !key.respond_to?(:sign)
      key
    end

    def build_headers(headers)
      return headers if headers.transform_keys(&:downcase).key?("user-agent")
      headers.merge({"user-agent" => "Linzer/#{Linzer::VERSION}"})
    end

    def build_request(method, uri, headers)
      request_class = Net::HTTP.const_get(method.to_s.capitalize)
      request = request_class.new(URI(uri))
      headers.map { |k, v| request[k] = v }
      request
    end

    def with_body?(verb)
      # common HTTP
      return false if %i[get head options trace delete].include?(verb)
      # WebDAV
      return false if %i[copy move].include?(verb)

      # everything else that could have a body:
      # common HTTP: post, put, patch
      # WebDAV:      lock, unlock, mkcol, propfind, proppatch
      true
    end

    def do_request(http, uri, verb, data, signature, headers)
      if with_body?(verb)
        if !data
          missed_body = "Missing request body on HTTP request: '#{verb.upcase}'"
          raise Linzer::Error, missed_body
        end
        http.public_send(verb, uri, data, headers.merge(signature.to_h))
      else
        http.public_send(verb, uri,       headers.merge(signature.to_h))
      end
    end
  end
end
