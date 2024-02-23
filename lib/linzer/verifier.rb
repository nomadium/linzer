# frozen_string_literal: true

module Linzer
  module Verifier
    class << self
      def verify(key, message, signature)
        validate message, key, signature

        parameters = signature.parameters
        components = signature.components

        signature_base = message.signature_base(components, parameters)

        return true if _verify(key, signature.value, signature_base)
        raise Error.new "Failed to verify message: Invalid signature."
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
      end

      def _verify(key, signature, data)
        # XXX to-do: get rid of this hard-coded SHA512 values, support more algs
        return true if key.material.verify_pss("SHA512", signature, data, salt_length: :auto, mgf1_hash: "SHA512")
        false
      end
    end
  end
end
