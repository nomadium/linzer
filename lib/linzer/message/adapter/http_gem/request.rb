# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module HTTPGem
        class Request < Linzer::Message::Adapter::NetHTTP::Request
          def headers
            @operation.headers.to_h
          end

          private

          def derived(name)
            return @operation.verb.to_s.upcase if name.value == :method
            super
          end
        end
      end
    end
  end
end
