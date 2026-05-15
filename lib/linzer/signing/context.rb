# frozen_string_literal: true

# XXX: This could be a struct
# XXX: Document
module Linzer
  module Signing
    class Context
      def initialize(message:, key:, label:, components:, params:)
        @message    = message
        @key        = key
        @components = components.dup
        @params     = label ? params.dup.merge(label: label) : params.dup
      end
      attr_reader :message, :key, :components, :params
    end
  end
end
