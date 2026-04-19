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

          # Attaches a signature to the response.
          # @param signature [Signature] The signature to attach
          # @return [Object] The underlying response object
          def attach!(signature)
            signature.to_h.each { |h, v| @operation.headers[h] = v }
            @operation
          end

          private

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
