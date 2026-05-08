# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Rack
        # Adapter for {::Rack::Request} objects.
        #
        # Handles the Rack-specific header naming conventions (HTTP_* prefix,
        # uppercase, underscores).
        class Request < Abstract
          include Common

          # Creates a new Rack request adapter.
          # @param operation [::Rack::Request] The Rack request
          # @param options [Hash] Additional options (unused)
          def initialize(operation, **options)
            @operation = operation
            validate
            freeze
          end

          # Retrieves a header value by name.
          # @param name [String] The header name (e.g., "content-type")
          # @return [String, nil] The header value
          def header(name)
            @operation.get_header(rack_header_name(name))
          end

          # Sets a header on the underlying HTTP message.
          #
          # If a header with the given name already exists, its value is overwritten.
          #
          # @param header [String] the header name
          # @param value [String] the header value
          # @return [String] the value assigned to the header
          def set_header!(header, value)
            @operation.set_header(rack_header_name(header), value)
          end
        end
      end
    end
  end
end
