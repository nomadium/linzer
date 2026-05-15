# frozen_string_literal: true

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

      # def params
      #   return @params if !@label
      #   @params.merge(label: @label)
      # end
    end
  end
end
