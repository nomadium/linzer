# frozen_string_literal: true

# Example HTTP message adapter for HTTP::Response class from http ruby gem.
# https://github.com/httprb/http
# It's not required automatically to avoid making http gem a dependency.
#
module Linzer
  class Message
    module Adapter
      module HTTPGem
        class Response < Abstract
          def initialize(operation, **options)
            @operation = operation
            freeze
          end

          def header(name)
            @operation[name]
          end

          # XXX: this implementation is incomplete, e.g.: ;tr parameter is not supported yet
          def [](field_name)
            return @operation.code if field_name == "@status"
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
