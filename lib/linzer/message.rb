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

    def validate_parameters(name, method)
      has_unknown = name.parameters.any? { |p, _| !KNOWN_PARAMETERS.include?(p) }
      return nil if has_unknown

      has_name = name.parameters["name"]
      has_req  = name.parameters["req"]
      has_sf   = name.parameters["sf"] || name.parameters.key?("key")
      has_bs   = name.parameters["bs"]
      value    = name.value

      # Section 2.2.8 of RFC 9421
      return nil if has_name && value != :"query-param"

      # No derived values come from trailers section
      return nil if method == :derived && name.parameters["tr"]

      # From: 2.1. HTTP Fields:
      # The bs parameter, which requires the raw bytes of the field values
      # from the message, is not compatible with the use of the sf or key
      # parameters, which require the parsed data structures of the field
      # values after combination
      return nil if has_sf && has_bs

      # req param only makes sense on responses with an associated request
      return nil if has_req && (!response? || !attached_request?)

      name
    end

    KNOWN_PARAMETERS = %w[sf key bs req tr name]
    private_constant :KNOWN_PARAMETERS

    def retrieve(name, method)
      if !name.parameters.empty?
        valid_params = validate_parameters(name, method)
        return nil if !valid_params
      end

      has_req = name.parameters["req"]
      has_sf  = name.parameters["sf"] || name.parameters.key?("key")
      has_bs  = name.parameters["bs"]

      if has_req
        name.parameters.delete("req")
        return req(name, method)
      end

      value = send(method, name)

      case
      when has_sf
        key = name.parameters["key"]
        sf(value, key)
      when has_bs then bs(value)
      else value
      end
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
      return "?" + value    if method == :query_string
      return value.downcase if %i[authority scheme].include?(method)
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

      if key
        obj = dict[key]
        Starry.serialize(obj.is_a?(Starry::InnerList) ? [obj] : obj)
      else
        Starry.serialize(dict)
      end
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
