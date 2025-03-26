# frozen_string_literal: true

module Linzer
  module Verifier
    class << self
      include Common

      def verify(key, message, signature, no_older_than: nil)
        validate message, key, signature

        parameters = signature.parameters
        components = signature.components

        if no_older_than && (Time.now.to_i - parameters["created"]) > no_older_than.to_i
          raise Error.new "Signature created more than #{no_older_than} seconds ago"
        end

        signature_base = signature_base(message, components, parameters)

        verify_or_fail key, signature.value, signature_base
      end

      private

      def validate(message, key, signature)
        raise Error.new "Message to verify cannot be null"       if message.nil?
        raise Error.new "Key to verify signature cannot be null" if key.nil?
        raise Error.new "Signature to verify cannot be null"     if signature.nil?

        if !signature.respond_to?(:value) || !signature.respond_to?(:components)
          raise Error.new "Signature is invalid"
        end

        raise Error.new "Signature raw value to cannot be null" if signature.value.nil?
        raise Error.new "Components cannot be null"             if signature.components.nil?

        validate_components message, signature.components
      end

      def verify_or_fail(key, signature, data)
        return true if key.verify(signature, data)
        raise Error.new "Failed to verify message: Invalid signature."
      end
    end
  end
end
