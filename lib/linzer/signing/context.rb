# frozen_string_literal: true

module Linzer
  module Signing
    class Context
      def initialize(message:, key:, label:, components:, params:)
        @message    = message
        @key        = key
        @label      = label
        @components = components
        @params     = params
      end
      attr_reader :message, :key, :components
  
      def params
        return @params if !@label
        @params.merge(label: @label)
      end
    end
  end
end
