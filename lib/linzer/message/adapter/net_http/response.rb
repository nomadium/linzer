# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module NetHTTP
        class Response < Generic::Response
          private

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
