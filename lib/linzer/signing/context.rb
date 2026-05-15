# frozen_string_literal: true

# XXX: This could be a struct
# XXX: Document
module Linzer
  module Signing
    class Context
      def initialize(message:, key:, label:, components:, params:)
        @message       = message
        @key           = key
        @components    = components.dup
        @params        = label ? params.dup.merge(label: label) : params.dup
        @extra_headers = {}
      end
      attr_reader :key, :components, :params, :extra_headers

      def message
        return @augmented_message if @augmented_message
        return @message           if extra_headers.empty?
        @augmented_message =      @message.with_headers(extra_headers)
      end
    end
  end
end
