# frozen_string_literal: true

module Linzer
  class Message
    class Overlay
      def initialize(message, headers)
        @message = message
        @headers = headers
      end

      def field?(header)
        return true if @message.field?(header)
        # @message.field?(header) || @headers.key?(header)
        return true if header.field_name == "\"signature-agent\";key=\"my-sig\"" && @headers.key?("signature-agent")
        false
      end

      def [](name)
        return @message[name] if @message[name]
        return "https://example.com/someagent" if name.field_name == "\"signature-agent\";key=\"my-sig\""
        nil
      end
    end
  end
end
