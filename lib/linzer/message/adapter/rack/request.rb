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

          def header(name)
            @operation.get_header(rack_header_name(name))
          end

          def attach!(signature)
            signature.to_h.each do |h, v|
              @operation.set_header(rack_header_name(h), v)
            end
            @operation
          end
        end
      end
    end
  end
end
