# frozen_string_literal: true

module Linzer
  class Message
    # Handles wrapping HTTP messages with the appropriate adapter.
    #
    # This module maintains a registry of adapter classes for different
    # HTTP message types (Rack, Net::HTTP, etc.) and selects the correct
    # one when wrapping a message.
    #
    # @api private
    module Wrapper
      # Default adapter mappings for built-in HTTP library support.
      @adapters = {
        Rack::Request     => Linzer::Message::Adapter::Rack::Request,
        Rack::Response    => Linzer::Message::Adapter::Rack::Response,
        Net::HTTPRequest  => Linzer::Message::Adapter::NetHTTP::Request,
        Net::HTTPResponse => Linzer::Message::Adapter::NetHTTP::Response
      }

      class << self
        # Wraps an HTTP message with the appropriate adapter.
        #
        # @param operation [Object] The HTTP request or response object
        # @param options [Hash] Additional options (e.g., :attached_request)
        # @return [Adapter::Abstract] The wrapped message
        # @raise [Error] If no suitable adapter is found
        def wrap(operation, **options)
          adapter_class = adapters[operation.class]

          if !adapter_class
            ancestor = find_ancestor(operation)
            fail_with_unsupported(operation) unless ancestor
          end

          (adapter_class || ancestor).new(operation, **options)
        end

        # Registers a custom adapter for an HTTP message class.
        #
        # @param operation_class [Class] The HTTP message class
        # @param adapter_class [Class] The adapter class to use
        def register_adapter(operation_class, adapter_class)
          adapters[operation_class] = adapter_class
        end

        private

        attr_reader :adapters

        # Finds an adapter by checking the operation's ancestry.
        #
        # This allows subclasses of registered classes (e.g.
        # +Net::HTTP::Get < Net::HTTPRequest+) to use the parent's adapter
        # without explicit registration.
        #
        # @param operation [Object] the HTTP message object
        # @return [Class, nil] the adapter class, or +nil+ if no ancestor matches
        def find_ancestor(operation)
          adapters
            .select { |klz, adpt| operation.is_a? klz }
            .values
            .first
        end

        # Raises an error for unsupported HTTP message types.
        #
        # @param operation [Object] the unsupported HTTP message
        # @raise [Linzer::Error] with a message suggesting +register_adapter+
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
