# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module HTTPGem
        # Adapter for {HTTP::Response} objects from http.rb gem.
        #
        # Extends the generic response adapter with http.rb-specific
        # status code retrieval.
        #
        # @note Not loaded automatically to avoid making http gem a dependency.
        #
        # @see https://github.com/httprb/http http.rb gem
        class Response < Generic::Response
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
