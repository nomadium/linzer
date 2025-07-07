# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module NetHTTP
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
