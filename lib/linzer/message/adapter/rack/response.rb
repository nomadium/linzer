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

          # Attaches a signature to the response.
          # @param signature [Signature] The signature to attach
          # @return [::Rack::Response] The response with signature headers
          def attach!(signature)
            signature.to_h.each do |h, v|
              @operation.set_header(h, v)
            end
            @operation
          end
        end
      end
    end
  end
end
