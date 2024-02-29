# frozen_string_literal: true

module Linzer
  class Message
    def initialize(request_data)
      @headers = Hash(request_data[:headers].clone).freeze
      @http    = Hash(request_data[:http].clone).freeze
      freeze
    end

    def empty?
      @headers.empty?
    end

    def header?(header)
      @headers.key?(header)
    end

    def field?(f)
      !!self[f]
    end

    def [](field_name)
      return @headers[field_name] if !field_name.start_with?("@")

      case field_name
      when "@method"    then @http["method"]
      when "@authority" then @http["host"]
      when "@path"      then @http["path"]
      when "@status"    then @http["status"]
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
