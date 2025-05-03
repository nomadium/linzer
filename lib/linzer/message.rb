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
    def_delegators :@adapter, :headers, :field?, :[]

    # to attach a signature to the underlying HTTP message
    def_delegators :@adapter, :attach!

    # maybe move this to a better place
    class << self
      def parse_structured_dictionary(str, field_name = nil)
        Starry.parse_dictionary(str)
      rescue Starry::ParseError => _
        raise Error.new "Cannot parse \"#{field_name}\" field. Bailing out!"
      end

      def register_adapter(operation_class, adapter_class)
        Wrapper.register_adapter(operation_class, adapter_class)
      end
    end
  end
end
