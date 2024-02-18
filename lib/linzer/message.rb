# frozen_string_literal: true

module Linzer
  class Message
    def initialize(request_data)
      @headers = Hash(request_data[:headers])
      @http = Hash(request_data[:http])
    end

    def empty?
      @headers.empty?
    end

    def header?(header)
      @headers.key?(header)
    end

    def [](field_name)
      return @headers[field_name] if !field_name.start_with?("@")

      case field_name
      when "@method" then @http["method"]
      when "@authority" then @http["host"]
      when "@path" then @http["path"]
      else # XXX: improve this and add support for all fields in the RFC
        raise Error.new "Unknown/unsupported field: \"#{field_name}\""
      end
    end
  end
end
