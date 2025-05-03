# frozen_string_literal: true

module Linzer
  class Message
    module Wrapper
      @adapters = {
        Rack::Request     => Linzer::Message::Adapter::Rack::Request,
        Rack::Response    => Linzer::Message::Adapter::Rack::Response,
        Net::HTTPRequest  => Linzer::Message::Adapter::NetHTTP::Request,
        Net::HTTPResponse => Linzer::Message::Adapter::NetHTTP::Response
      }

      class << self
        def wrap(operation, **options)
          adapter_class = adapters[operation.class]

          if !adapter_class
            ancestor = find_ancestor(operation)
            fail_with_unsupported(operation) unless ancestor
          end

          (adapter_class || ancestor).new(operation, **options)
        end

        def register_adapter(operation_class, adapter_class)
          adapters[operation_class] = adapter_class
        end

        private

        attr_reader :adapters

        def find_ancestor(operation)
          adapters
            .select { |klz, adpt| operation.is_a? klz }
            .values
            .first
        end

        def fail_with_unsupported(operation)
          err_msg = <<~EOM
            Unknown/unsupported HTTP message class: '#{operation.class}'!

            Linzer supports custom HTTP messages implementation by register them first
            with `Linzer::Message.register_adapter` method.
          EOM
          raise Linzer::Error, err_msg
        end
      end
    end
  end
end
