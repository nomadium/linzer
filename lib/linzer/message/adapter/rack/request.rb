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

          # Attaches a signature to the request.
          # @param signature [Signature] The signature to attach
          # @return [::Rack::Request] The request with signature headers
          def attach!(signature)
            signature.to_h.each do |h, v|
              @operation.set_header(rack_header_name(h), v)
            end
            @operation
          end
        end
      end
    end
  end
end
