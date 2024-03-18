# frozen_string_literal: true

module Linzer
  module Request
    def new_request(verb, uri = "/", params = {}, headers = {})
      request_method = Rack.const_get(verb.upcase)
      args = {
        "REQUEST_METHOD" => request_method,
        "PATH_INFO" => uri
      }
      env = build_rack_env(headers)
      Rack::Request.new(env.merge(args))
    end

    class << self
      def rack_header_name(field_name)
        rack_name = field_name.upcase.tr("-", "_")
        case field_name
        when "content-type", "content-length"
          rack_name
        else
          "HTTP_#{rack_name}"
        end
      end
    end

    private

    def build_rack_env(headers)
      headers
        .to_h
        .transform_keys { |k| k.upcase.tr("-", "_") }
        .transform_keys do |k|
          %w[CONTENT_TYPE CONTENT_LENGTH].include?(k) ? k : "HTTP_#{k}"
        end
    end
  end
end
