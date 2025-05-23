# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Rack
        class Response < Abstract
          include Common

          def initialize(operation, **options)
            @operation = operation
            validate
            attached_request = options[:attached_request]
            @attached_request = attached_request ? Message.new(attached_request) : nil
            validate_attached_request @attached_request if @attached_request
            freeze
          end

          def header(name)
            @operation.get_header(name)
          end

          def attach!(signature)
            signature.to_h.each do |h, v|
              @operation.set_header(h, v)
            end
            @operation
          end
        end
      end
    end
  end
end
