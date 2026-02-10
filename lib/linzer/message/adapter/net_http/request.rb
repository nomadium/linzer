# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      # Net::HTTP message adapters.
      #
      # Provides adapters for {Net::HTTPRequest} and {Net::HTTPResponse} objects.
      module NetHTTP
        # Adapter for {Net::HTTPRequest} objects.
        #
        # Extends the generic request adapter with Net::HTTP-specific
        # method name retrieval.
        class Request < Generic::Request
          private

          def derived(name)
            return @operation.method if name.value == "@method"
            super
          end
        end
      end
    end
  end
end
