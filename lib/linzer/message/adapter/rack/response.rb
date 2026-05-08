# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Rack
        # Adapter for {::Rack::Response} objects.
        class Response < Abstract
          include Common

          # Creates a new Rack response adapter.
          # @param operation [::Rack::Response] The Rack response
          # @param options [Hash] Additional options
          # @option options [Object] :attached_request Request for `;req` support
          def initialize(operation, **options)
            @operation = operation
            validate
            attached_request = options[:attached_request]
            @attached_request = attached_request ? Message.new(attached_request) : nil
            validate_attached_request @attached_request if @attached_request
            freeze
          end

          # Retrieves a header value by name.
          # @param name [String] The header name
          # @return [String, nil] The header value
          def header(name)
            @operation.get_header(name)
          end

          # Sets a header on the underlying HTTP message.
          #
          # If a header with the given name already exists, its value is overwritten.
          #
          # @param header [String] the header name
          # @param value [String] the header value
          # @return [String] the value assigned to the header
          def set_header!(header, value)
            @operation.set_header(header, value)
          end
        end
      end
    end
  end
end
