# frozen_string_literal: true

require "forwardable"

module Linzer
  # Wraps an HTTP request or response for signing and verification.
  #
  # Message provides a unified interface for accessing HTTP message components
  # regardless of the underlying HTTP library (Rack, Net::HTTP, http.rb, etc.).
  # It handles the extraction of both regular header fields and derived
  # components (like `@method`, `@path`, `@authority`).
  #
  # @example Wrapping a Rack request
  #   request = Rack::Request.new(env)
  #   message = Linzer::Message.new(request)
  #   message.request?  # => true
  #   message["@method"] # => "GET"
  #
  # @example Wrapping a Net::HTTP request
  #   request = Net::HTTP::Post.new(uri)
  #   request["content-type"] = "application/json"
  #   message = Linzer::Message.new(request)
  #   message["content-type"]  # => "application/json"
  #
  # @example Wrapping a response with an attached request
  #   response = Net::HTTPOK.new("1.1", "200", "OK")
  #   message = Linzer::Message.new(response, attached_request: request)
  #   message["@status"]  # => 200
  #   message['"content-type";req']  # => value from the attached request
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2 RFC 9421 Section 2
  class Message
    extend Forwardable

    # Creates a new Message wrapper.
    #
    # @param operation [Rack::Request, Rack::Response, Net::HTTPRequest,
    #   Net::HTTPResponse, HTTP::Request, HTTP::Response] The HTTP message to wrap.
    #   Linzer automatically selects the appropriate adapter based on the class.
    # @param attached_request [Object, nil] For response messages, an optional
    #   request that can be referenced using the `;req` parameter in component
    #   identifiers. This enables signing responses that cover request fields.
    #
    # @raise [Error] If the operation class is not supported and no adapter
    #   has been registered for it.
    #
    # @example Basic usage
    #   message = Linzer::Message.new(request)
    #
    # @example Response with attached request (for `;req` parameter support)
    #   message = Linzer::Message.new(response, attached_request: original_request)
    def initialize(operation, attached_request: nil)
      @adapter = Wrapper.wrap(operation, attached_request: attached_request)
      freeze
    end

    # @!method request?
    #   Checks if this message wraps an HTTP request.
    #   @return [Boolean] true if the underlying message is a request

    # @!method response?
    #   Checks if this message wraps an HTTP response.
    #   @return [Boolean] true if the underlying message is a response

    # @!method attached_request?
    #   Checks if this response message has an attached request.
    #   @return [Boolean] true if an attached request is present
    def_delegators :@adapter, :request?, :response?, :attached_request?

    # @!method header(name)
    #   Retrieves a header value by name.
    #   @param name [String] The header name (case-insensitive)
    #   @return [String, nil] The header value, or nil if not present

    # @!method field?(component)
    #   Checks if a component exists in the message.
    #   @param component [String] The component identifier
    #   @return [Boolean] true if the component can be retrieved

    # @!method [](component)
    #   Retrieves a component value from the message.
    #
    #   Supports both regular header fields and derived components:
    #   - Header fields: `"content-type"`, `"date"`, `"x-custom-header"`
    #   - Derived components: `"@method"`, `"@path"`, `"@authority"`, `"@status"`
    #   - With parameters: `"content-type";bs`, `"example-dict";key="a"`, `"date";req`
    #
    #   @param component [String] The component identifier, optionally with parameters
    #   @return [String, Integer, nil] The component value, or nil if not found
    #
    #   @example Accessing headers
    #     message["content-type"]  # => "application/json"
    #
    #   @example Accessing derived components
    #     message["@method"]  # => "POST"
    #     message["@path"]    # => "/api/resource"
    #
    #   @example With parameters
    #     message['"content-type";bs']  # => base64-encoded value
    def_delegators :@adapter, :header, :field?, :[]

    # @!method attach!(signature)
    #   Attaches a signature to the underlying HTTP message.
    #
    #   Modifies the original HTTP message by adding the `signature` and
    #   `signature-input` headers from the signature.
    #
    #   @param signature [Linzer::Signature] The signature to attach
    #   @return [Object] The underlying HTTP message object
    #
    #   @example
    #     signature = Linzer.sign(key, message, components)
    #     message.attach!(signature)
    def_delegators :@adapter, :attach!

    # XXX: to-do document
    def with_headers(headers)
      Overlay.new(self, headers)
    end

    class << self
      # Registers a custom adapter for an HTTP message class.
      #
      # Use this to add support for HTTP libraries not built into Linzer.
      # The adapter class must inherit from {Adapter::Abstract} and implement
      # the required interface.
      #
      # @param operation_class [Class] The HTTP message class to register
      # @param adapter_class [Class] The adapter class to use for wrapping
      #
      # @example Registering a custom adapter
      #   class MyHttpRequest; end
      #   class MyAdapter < Linzer::Message::Adapter::Abstract
      #     # ... implementation
      #   end
      #   Linzer::Message.register_adapter(MyHttpRequest, MyAdapter)
      #
      # @see Adapter::Abstract
      def register_adapter(operation_class, adapter_class)
        Wrapper.register_adapter(operation_class, adapter_class)
      end
    end
  end
end
