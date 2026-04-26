# frozen_string_literal: true

require "linzer/message/adapter/http_gem/common"

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
          include HTTPGem::Common

          private

          # Resolves a derived component value from the response.
          #
          # Uses +HTTP::Response#status+ converted to Integer for
          # the +@status+ component.
          #
          # @param name [Starry::Item] the parsed component identifier
          # @return [Integer, nil] the HTTP status code, or +nil+ if unknown
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
