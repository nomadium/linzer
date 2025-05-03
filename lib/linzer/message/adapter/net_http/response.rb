# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module NetHTTP
        class Response < Abstract
          def initialize(operation, **options)
            @operation = operation
            attached_request = options[:attached_request]
            @attached_request = attached_request ? Message.new(attached_request) : nil
            validate_attached_request @attached_request if @attached_request
            freeze
          end

          def headers
            @operation.each_header.to_h
          end

          # XXX: this implementation is incomplete, e.g.: ;tr parameter is not supported yet
          def [](field_name)
            return @operation.code.to_i if field_name == "@status"
            @operation[field_name]
          end

          def attach!(signature)
            signature.to_h.each { |h, v| @operation[h] = v }
            @operation
          end
        end
      end
    end
  end
end
