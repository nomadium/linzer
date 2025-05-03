# frozen_string_literal: true

module Linzer
  class Message
    module Adapter
      module Rack
        module Common
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
          private_constant :DERIVED_COMPONENT

          private

          def validate
            msg = "Message instance must be an HTTP request or response"
            raise Error.new msg if response? == request?
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
                rack_header_name = Linzer::Request.rack_header_name(name.value.to_s)
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
        end
      end
    end
  end
end
