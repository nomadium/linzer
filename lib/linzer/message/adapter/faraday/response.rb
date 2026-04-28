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
        end
      end
    end
  end
end
