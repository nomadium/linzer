# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Rack
        class Request < Abstract
          include Common

          def initialize(operation, **options)
            @operation = operation
            validate
            freeze
          end

          def headers
            Linzer::Request.headers(@operation)
          end

          def attach!(signature)
            signature.to_h.each do |h, v|
              @operation.set_header(Linzer::Request.rack_header_name(h), v)
            end
            @operation
          end
        end
      end
    end
  end
end
