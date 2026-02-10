# frozen_string_literal: true

require "net/http"

module Linzer
  # Simple HTTP client with automatic request signing.
  #
  # This module provides convenience methods for making signed HTTP requests
  # using Net::HTTP. It automatically signs outgoing requests with the
  # provided key.
  #
  # For each standard HTTP method (GET, POST, PUT, DELETE, etc.), a
  # corresponding method is dynamically defined.
  #
  # @example Making a signed GET request
  #   key = Linzer.generate_ed25519_key("my-key")
  #   response = Linzer::HTTP.get("https://example.com/api", key: key)
  #
  # @example Making a signed POST request with body
  #   response = Linzer::HTTP.post("https://example.com/api",
  #     key: key,
  #     data: { "name" => "value" }.to_json,
  #     headers: { "Content-Type" => "application/json" }
  #   )
  #
  # @example Customizing covered components
  #   response = Linzer::HTTP.get("https://example.com/api",
  #     key: key,
  #     covered_components: %w[@method @authority @path date content-type]
  #   )
  #
  # @see SignatureFeature For http.rb gem integration
  module HTTP
    extend self

    # Returns the list of known HTTP methods from Net::HTTP.
    # @return [Array<String>] HTTP method names (e.g., "GET", "POST")
    def self.known_http_methods
      Net::HTTP
        .constants
        .map    { |const| Net::HTTP.const_get(const) }
        .select { |klass| klass.is_a?(Class) && klass.const_defined?(:METHOD) }
        .map    { |klass| klass::METHOD }
        .freeze
    end

    # Dynamically define methods for each HTTP verb (get, post, put, etc.)
    #
    # @!method get(uri, options)
    #   Makes a signed GET request.
    #   @param uri [String] The request URI
    #   @param options [Hash] Request options
    #   @option options [Key] :key The signing key (required)
    #   @option options [Hash] :headers Additional headers
    #   @option options [Array<String>] :covered_components Components to sign
    #   @option options [Hash] :params Additional signature parameters
    #   @option options [Boolean] :debug Enable debug output
    #   @return [Net::HTTPResponse] The response
    #
    # @!method post(uri, options)
    #   Makes a signed POST request.
    #   @param uri [String] The request URI
    #   @param options [Hash] Request options
    #   @option options [Key] :key The signing key (required)
    #   @option options [String] :data Request body (required for POST)
    #   @option options [Hash] :headers Additional headers
    #   @option options [Array<String>] :covered_components Components to sign
    #   @option options [Hash] :params Additional signature parameters
    #   @return [Net::HTTPResponse] The response
    known_http_methods.each do |http_method|  # e.g.:
      method = http_method.downcase.to_sym    #
      define_method(method) do |uri, options| # def post(uri, **options)
        options ||= {}                        #   request :post, uri, options
        request method, uri, options          # end
      end
    end

    private

    # Executes a signed HTTP request.
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

    # Determines if the HTTP method typically has a request body.
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
