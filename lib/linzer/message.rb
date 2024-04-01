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

    DERIVED_COMPONENT = {
      "@method"         => :request_method,
      "@authority"      => :authority,
      "@path"           => :path_info,
      "@status"         => :status,
      "@target-uri"     => :url,
      "@scheme"         => :scheme,
      "@request-target" => :fullpath,
      "@query"          => :query_string
    }.freeze

    def [](field_name)
      if !field_name.start_with?("@")
        return @operation.env[Request.rack_header_name(field_name)] if request?
        return @operation.headers[field_name]                     # if response?
      end

      method = DERIVED_COMPONENT[field_name]

      case field_name
      when "@query"
        return "?#{@operation.public_send(method)}"
      when /\A(?<field>(?<prefix>@query-param)(?<rest>;name=.+)\Z)/
        return parse_query_param Regexp.last_match
      end

      method ? @operation.public_send(method) : nil
    end

    class << self
      def parse_structured_dictionary(str, field_name = nil)
        Starry.parse_dictionary(str)
      rescue Starry::ParseError => _
        raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
      end
    end

    private

    def parse_query_param(match_data)
      raw_item    = '"%s"%s' % [match_data[:prefix], match_data[:rest]]
      parsed_item = Starry.parse_item(raw_item)
      fail unless parsed_item.value == "@query-param"
      param_name  = URI.decode_uri_component(parsed_item.parameters["name"])
      URI.encode_uri_component(@operation.params.fetch(param_name))
    rescue => _
      nil
    end
  end
end
