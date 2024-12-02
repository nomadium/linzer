# frozen_string_literal: true

module Linzer
  module Request
    extend self

    def build(verb, uri = "/", params = {}, headers = {})
      validate verb, uri, params, headers

      # XXX: to-do: handle rack request params?
      request_method = Rack.const_get(verb.upcase)
      args = {
        "REQUEST_METHOD" => request_method,
        "PATH_INFO"      => uri.to_str,
        "rack.input"     => StringIO.new
      }

      Rack::Request.new(build_rack_env(headers).merge(args))
    end

    def rack_header_name(field_name)
      validate_header_name field_name

      rack_name = field_name.upcase.tr("-", "_")
      case field_name.downcase
      when "content-type", "content-length"
        rack_name
      else
        "HTTP_#{rack_name}"
      end
    end

    def headers(rack_request)
      rack_request
        .each_header
        .to_h
        .select do |k, _|
          k.start_with?("HTTP_") || %w[CONTENT_TYPE CONTENT_LENGTH].include?(k)
        end
        .transform_keys { |k| k.downcase.tr("_", "-") }
        .transform_keys do |k|
          %w[content-type content-length].include?(k) ? k : k.gsub(/^http-/, "")
        end
    end

    private

    def validate(verb, uri, params, headers)
      validate_verb      verb
      validate_uri       uri
      validate_arg_hash  headers: headers
      validate_arg_hash  params:  params
    end

    def validate_verb(verb)
      Rack.const_get(verb.upcase)
    rescue => ex
      unknown_method = "Unknown/invalid HTTP request method"
      raise Error.new, unknown_method, cause: ex
    end

    def validate_uri(uri)
      uri.to_str
    rescue => ex
      invalid_uri = "Invalid URI"
      raise Error.new, invalid_uri, cause: ex
    end

    def validate_arg_hash(hsh)
      arg_name = hsh.keys.first
      hsh[arg_name].to_hash
    rescue => ex
      err_msg = "invalid \"#{arg_name}\" parameter, cannot be converted to hash."
      raise Error.new, "Cannot build request: #{err_msg}", cause: ex
    end

    def validate_header_name(name)
      raise ArgumentError.new, "Blank header name." if name.empty?
      name.to_str
    rescue => ex
      err_msg = "Invalid header name: '#{name}'"
      raise Error.new, err_msg, cause: ex
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
