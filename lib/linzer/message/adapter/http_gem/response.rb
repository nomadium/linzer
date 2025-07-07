# frozen_string_literal: true

# HTTP message adapter for HTTP::Response class from http ruby gem.
# https://github.com/httprb/http
#
# It's not loaded automatically to avoid making http gem a dependency.
#
module Linzer
  class Message
    module Adapter
      module HTTPGem
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
