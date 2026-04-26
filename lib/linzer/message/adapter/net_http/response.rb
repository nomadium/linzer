# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module NetHTTP
        # Adapter for {Net::HTTPResponse} objects.
        #
        # Extends the generic response adapter with Net::HTTP-specific
        # status code retrieval.
        class Response < Generic::Response
          private

          # Resolves a derived component value from the response.
          #
          # Uses +Net::HTTPResponse#code+ (a String) converted to Integer
          # for the +@status+ component.
          #
          # @param name [Starry::Item] the parsed component identifier
          # @return [Integer, nil] the HTTP status code, or +nil+ if unknown
          def derived(name)
            case name.value
            when "@status" then @operation.code.to_i
            end
          end
        end
      end
    end
  end
end
