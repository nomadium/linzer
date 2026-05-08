# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Generic
        # Generic HTTP response adapter.
        #
        # Provides a base implementation for response message access.
        # Assumes the operation responds to `[]` for header access.
        #
        # @abstract Subclass must implement {#derived} method.
        class Response < Abstract
          # Creates a new response adapter.
          # @param operation [Object] The HTTP response object
          # @param options [Hash] Additional options
          # @option options [Object] :attached_request An associated request
          #   for `;req` parameter support
          def initialize(operation, **options)
            @operation = operation
            attached_request = options[:attached_request]
            @attached_request = attached_request ? Message.new(attached_request) : nil
            validate_attached_request @attached_request if @attached_request
            freeze
          end

          # Retrieves a header value by name.
          # @param name [String] The header name
          # @return [String, nil] The header value
          def header(name)
            @operation[name]
          end

          # Sets a header on the underlying HTTP message.
          #
          # If a header with the given name already exists, its value is overwritten.
          #
          # @param header [String] the header name
          # @param value [String] the header value
          # @return [String] the value assigned to the header
          def set_header!(header, value)
            @operation[header] = value
          end

          private

          def derived(name)
            raise Linzer::Error, "Sub-classes are required to implement this method!"
          end

          def field(name)
            has_tr = name.parameters["tr"]
            return nil if has_tr # is there a library actually supporting trailers?
            value = @operation[name.value.to_s]
            value.dup&.strip
          end
        end
      end
    end
  end
end
