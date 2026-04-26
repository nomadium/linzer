# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Faraday
        # Adapter for {::Faraday::Response} objects from the faraday gem.
        #
        # Extends the generic response adapter with faraday-specific
        # derived component retrieval (e.g. +@status+) and header
        # attachment.
        #
        # @note Not loaded automatically to avoid making faraday a hard
        #   dependency. Require +"linzer/faraday"+ to register this adapter.
        #
        # @see Generic::Response
        # @see https://github.com/lostisland/faraday faraday gem
        class Response < Generic::Response
          # Attaches a signature to the underlying response headers.
          #
          # @param signature [Linzer::Signature] the signature to attach
          # @return [::Faraday::Response] the underlying response object
          def attach!(signature)
            signature.to_h.each { |h, v| @operation.headers[h] = v }
            @operation
          end

          private

          # Resolves a derived component value from the response.
          #
          # @param name [Starry::Item] the parsed component identifier
          # @return [Integer, nil] the HTTP status code for +@status+,
          #   or +nil+ if the component is unknown
          def derived(name)
            case name.value
            when "@status" then @operation.status.to_i
            end
          end
        end
      end
    end
  end
end
