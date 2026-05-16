# frozen_string_literal: true

module Linzer
  class Message
    class Overlay < Adapter::Generic::Request
      # class Overlay
      def initialize(message, headers)
        @message = message
        # @headers = headers
        @headers = Headers.new(headers)
      end

      def header(name)
        # binding.irb
        @headers[name]
      end

      def field?(header)
        return true if @message.field?(header)
        super
      end

      def attach!(signature)
        @message.attach!(signature, additional_headers: @headers)
      end

      #       def field?(header)
      #         return true if @message.field?(header)
      #         binding.irb
      #         # @message.field?(header) || @headers.key?(header)
      #         return true if header.field_name == "\"signature-agent\";key=\"my-sig\"" && @headers.key?("signature-agent")
      #         false
      #       end

      #       def [](name)
      #         return @message[name] if @message[name]
      #         binding.irb
      #         # field_id = (field.is_a?(FieldId) || field.is_a?(Field::FastIdentifier)) ? field : parse_field_name(field)
      #         # retrieve(field_id.item, field_id.derived? ? :derived : :field)
      #         return "https://example.com/someagent" if name.field_name == "\"signature-agent\";key=\"my-sig\""
      #         nil
      #       end

      def [](name)
        return @message[name] if @message[name]
        super
      end

      class Headers
        include Net::HTTPHeader

        def initialize(headers)
          initialize_http_header(headers)
        end

        def empty?
          @header.empty?
        end
      end
    end
  end
end
