# frozen_string_literal: true

require "forwardable"

module Linzer
  class Message
    extend Forwardable

    def initialize(operation, attached_request: nil)
      @adapter = Wrapper.wrap(operation, attached_request: attached_request)
      freeze
    end

    # common predicates
    def_delegators :@adapter, :request?, :response?, :attached_request?

    # fields look up
    def_delegators :@adapter, :header, :field?, :[]

    # to attach a signature to the underlying HTTP message
    def_delegators :@adapter, :attach!

    class << self
      def register_adapter(operation_class, adapter_class)
        Wrapper.register_adapter(operation_class, adapter_class)
      end
    end
  end
end
