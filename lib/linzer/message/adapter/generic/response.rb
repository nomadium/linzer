# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Generic
        class Response < Abstract
          def initialize(operation, **options)
            @operation = operation
            attached_request = options[:attached_request]
            @attached_request = attached_request ? Message.new(attached_request) : nil
            validate_attached_request @attached_request if @attached_request
            freeze
          end

          def header(name)
            @operation[name]
          end

          def attach!(signature)
            signature.to_h.each { |h, v| @operation[h] = v }
            @operation
          end

          private

          def derived(name)
            raise Linzer::Error, "Sub-classes are required to implement this method!"
          end

          # XXX: this implementation is incomplete, e.g.: ;bs parameter is not supported yet
          def field(name)
            has_tr = name.parameters["tr"]
            return nil if has_tr # Net::HTTP doesn't support trailers
            value = @operation[name.value.to_s]
            value.dup&.strip
          end
        end
      end
    end
  end
end
