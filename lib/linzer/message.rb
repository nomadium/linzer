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
      else # XXX: improve this and add support for all fields in the RFC
        raise Error.new "Unknown/unsupported field: \"#{field_name}\""
      end
    end

    def signature_base(components, parameters)
      validate_components components

      signature_base = components.each_with_object(+"") do |comp, base|
        base << "\"#{comp}\": #{self[comp]}\n"
      end

      signature_params =
        Starry.serialize([Starry::InnerList.new(components, parameters)])

      signature_base << "\"@signature-params\": #{signature_params}"
      signature_base
    end

    class << self
      def parse_structured_dictionary(str, field_name = nil)
        Starry.parse_dictionary(str)
      rescue Starry::ParseError => _
        raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
      end
    end

    private

    def validate_components(components)
      if components.include?("@signature-params")
        raise Error.new "Invalid component in signature input"
      end
      msg = "Cannot verify signature. Missing component in message: %s"
      components.each { |c| raise Error.new msg % "\"#{c}\"" unless field? c  }
      msg = "Invalid signature. Duplicated component in signature input."
      raise Error.new msg if components.size != components.uniq.size
    end
  end
end
