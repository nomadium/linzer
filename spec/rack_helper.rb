# frozen_string_literal: true

module Linzer
  module Test
    module RackHelper
      extend self

      def new_request(verb, path = "/", params = {}, headers = {})
        validate verb, path, params, headers

        # XXX: to-do: handle rack request params?
        request_method = Rack.const_get(verb.upcase)
        args = {
          "REQUEST_METHOD" => request_method,
          "PATH_INFO"      => path.to_str,
          "rack.input"     => StringIO.new
        }

        Rack::Request.new(build_rack_env(headers).merge(args))
      end

      def new_response(body = nil, status = 200, headers = {})
        Rack::Response.new(body, status, build_rack_env(headers))
      end

      private

      def validate(verb, path, params, headers)
        validate_verb      verb
        validate_path      path
        validate_arg_hash  headers: headers
        validate_arg_hash  params:  params
      end

      def validate_verb(verb)
        Rack.const_get(verb.upcase)
      rescue => ex
        unknown_method = "Unknown/invalid HTTP request method"
        raise Error.new, unknown_method, cause: ex
      end

      def validate_path(path)
        path.to_str
      rescue => ex
        invalid_path = "Invalid path"
        raise Error.new, invalid_path, cause: ex
      end

      def validate_arg_hash(hsh)
        arg_name = hsh.keys.first
        hsh[arg_name].to_hash
      rescue => ex
        err_msg = "invalid \"#{arg_name}\" parameter, cannot be converted to hash."
        raise Error.new, "Cannot build request: #{err_msg}", cause: ex
      end

      def build_rack_env(headers)
        headers
          .to_hash
          .transform_values(&:to_s)
          .transform_keys { |k| k.upcase.tr("-", "_") }
          .transform_keys do |k|
            %w[CONTENT_TYPE CONTENT_LENGTH].include?(k) ? k : "HTTP_#{k}"
          end
      end
    end
  end
end
