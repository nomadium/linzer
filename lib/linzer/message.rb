# frozen_string_literal: true

module Linzer
  class Message
    def initialize(operation)
      @operation = operation
      freeze
    end

    def request?
      @operation.is_a?(Rack::Request) || @operation.respond_to?(:request_method)
    end

    def response?
      @operation.is_a?(Rack::Response) || @operation.respond_to?(:status)
    end

    def headers
      return @operation.headers if response? || @operation.respond_to?(:headers)

      Request.headers(@operation)
    end

    def field?(f)
      !!self[f]
    end

    def [](field_name)
      if !field_name.start_with?("@")
        return @operation.env[Request.rack_header_name(field_name)] if request?
        return @operation.headers[field_name]                     # if response?
      end

      case field_name
      when "@method"    then @operation.request_method
      when "@authority" then @operation.authority
      when "@path"      then @operation.path_info
      when "@status"    then @operation.status
      else # XXX: improve this and add support for all fields in the RFC
        raise Error.new "Unknown/unsupported field: \"#{field_name}\""
      end
    end

    class << self
      def parse_structured_dictionary(str, field_name = nil)
        Starry.parse_dictionary(str)
      rescue Starry::ParseError => _
        raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
      end
    end
  end
end
