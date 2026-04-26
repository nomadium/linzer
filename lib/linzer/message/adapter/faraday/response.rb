# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Faraday
        # Adapter for {Faraday::Response} objects from faraday gem.
        #
        # Extends the generic response adapter with faraday-specific
        # status code retrieval.
        #
        # @note Not loaded automatically to avoid making faraday gem a dependency.
        #
        # @see https://github.com/lostisland/faraday faraday gem
        class Response < Generic::Response
          # Attaches a signature to the response.
          # @param signature [Signature] The signature to attach
          # @return [Object] The underlying response object
          def attach!(signature)
            signature.to_h.each { |h, v| @operation.headers[h] = v }
            @operation
          end

          private

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
