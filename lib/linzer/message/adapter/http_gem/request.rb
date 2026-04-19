# frozen_string_literal: true

require "linzer/message/adapter/http_gem/common"

module Linzer
  class Message
    module Adapter
      module HTTPGem
        # Adapter for {HTTP::Request} objects from http.rb gem.
        #
        # Extends the generic request adapter with http.rb-specific
        # method name retrieval.
        class Request < Generic::Request
          include HTTPGem::Common

          private

          def derived(name)
            return @operation.uri.host         if name.value == "@authority"
            return @operation.verb.to_s.upcase if name.value == "@method"
            super
          end
        end
      end
    end
  end
end
