# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      # http.rb gem message adapters.
      #
      # Provides adapters for {HTTP::Request} and {HTTP::Response} objects
      # from the http.rb gem.
      #
      # @note These adapters are loaded on-demand when using the
      #   {Linzer::HTTP::SignatureFeature}.
      module HTTPGem
        # Shared functionality for http.rb request and response adapters.
        module Common
          # Retrieves a header value by name.
          # @param name [String] The header name
          # @return [String, nil] The header value
          def header(name)
            @operation.headers[name]
          end

          # Sets a header on the underlying HTTP message.
          #
          # If a header with the given name already exists, its value is overwritten.
          #
          # @param header [String] the header name
          # @param value [String] the header value
          # @return [String] the value assigned to the header
          def set_header!(header, value)
            @operation.headers[header] = value
          end

          private

          # Retrieves an HTTP field value from the request or response headers.
          #
          # @param name [Starry::Item] the parsed component identifier
          # @return [String, nil] the stripped header value, or +nil+ if the
          #   field has a +tr+ (trailer) parameter or is not present
          def field(name)
            has_tr = name.parameters["tr"]
            return nil if has_tr # XXX: is there a library actually supporting trailers?
            value = @operation.headers[name.value.to_s]
            value.dup&.strip
          end
        end
      end
    end
  end
end
