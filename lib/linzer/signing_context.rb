# frozen_string_literal: true

module Linzer
  class SigningContext
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
