# frozen_string_literal: true

module Linzer
  class Message
    def initialize(operation, attached_request: nil)
      @operation = operation
      validate
      @attached_request = attached_request ? Message.new(attached_request) : nil
      freeze
    end

    def request?
      @operation.is_a?(Rack::Request) || @operation.respond_to?(:request_method)
    end

    def response?
      @operation.is_a?(Rack::Response) || @operation.respond_to?(:status)
    end

    def attached_request?
      !!@attached_request
    end

    def headers
      return @operation.headers if response? || @operation.respond_to?(:headers)

      Request.headers(@operation)
    end

    def field?(f)
      !!self[f]
    end

    DERIVED_COMPONENT = {
      method:           :request_method,
      authority:        :authority,
      path:             :path_info,
      status:           :status,
      "target-uri":     :url,
      scheme:           :scheme,
      "request-target": :fullpath,
      query:            :query_string
    }.freeze

    def [](field_name)
      name = parse_field_name(field_name)
      return nil if name.nil?

      if field_name.start_with?("@")
        return nil if name.parameters["tr"]
        retrieve(name, :derived)
      else
        retrieve(name, :field)
      end
    end

    class << self
      def parse_structured_dictionary(str, field_name = nil)
        Starry.parse_dictionary(str)
      rescue Starry::ParseError => _
        raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
      end
    end

    private

    def validate
      msg = "Message instance must be an HTTP request or response"
      raise Error.new msg if response? == request?
    end

    def parse_field_name(field_name)
      if field_name&.start_with?("@")
        Starry.parse_item(field_name[1..])
      else
        Starry.parse_item(field_name)
      end
    rescue => _
      nil
    end

    def retrieve(name, method)
      has_req = name.parameters["req"]
      has_sf  = name.parameters["sf"] || name.parameters.key?("key")
      has_bs  = name.parameters["bs"]

      return nil if has_req && (!response? || !attached_request?)

      if has_req
        name.parameters.delete("req")
        return req(name, method)
      end

      value = send(method, name)

      key = name.parameters["key"]
      value = sf(value, key) if has_sf
      value = bs(value)      if has_bs
      value
    end

    def derived(name)
      method = DERIVED_COMPONENT[name.value]

      value = case name.value
      when :query         then derive(@operation, method)
      when :"query-param" then query_param(name)
      end

      return nil if !method && !value
      value || derive(@operation, method)
    end

    def field(name)
      has_tr = name.parameters["tr"]
      if has_tr
        value = tr(name)
      else
        if request?
          rack_header_name = Request.rack_header_name(name.value.to_s)
          value = @operation.env[rack_header_name]
        end
        value = @operation.headers[name.value.to_s] if response?
      end
      value.dup&.strip
    end

    def derive(operation, method)
      return nil unless operation.respond_to?(method)
      value = operation.public_send(method)
      return "?" + value if method == :query_string
      value
    end

    def query_param(name)
      param_name = name.parameters["name"]
      return nil if !param_name
      decoded_param_name = URI.decode_uri_component(param_name)
      URI.encode_uri_component(@operation.params.fetch(decoded_param_name))
    rescue => _
      nil
    end

    def sf(value, key = nil)
      dict = Starry.parse_dictionary(value)

      obj = dict[key] if key
      return Starry.serialize(obj.is_a?(Starry::InnerList) ? [obj] : obj) if key

      Starry.serialize(dict)
    end

    def bs(value)
      Starry.serialize(value.encode(Encoding::ASCII_8BIT))
    end

    def tr(trailer)
      @operation.body.trailers[trailer.value.to_s]
    end

    def req(field, method)
      case method
      when :derived then @attached_request["@#{field}"]
      when :field   then @attached_request[field.to_s]
      end
    end
  end
end
