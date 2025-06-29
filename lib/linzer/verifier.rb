# frozen_string_literal: true

module Linzer
  module Verifier
    class << self
      include Common

      def verify(key, message, signature, no_older_than: nil)
        validate message, key, signature, no_older_than: no_older_than

        parameters = signature.parameters
        serialized_components = signature.serialized_components

        signature_base = signature_base(message, serialized_components, parameters)

        verify_or_fail key, signature.value, signature_base
      end

      private

      def validate(message, key, signature, no_older_than: nil)
        raise VerifyError, "Message to verify cannot be null"       if message.nil?
        raise VerifyError, "Key to verify signature cannot be null" if key.nil?
        raise VerifyError, "Signature to verify cannot be null"     if signature.nil?

        if !signature.respond_to?(:value) || !signature.respond_to?(:components)
          raise VerifyError, "Signature is invalid"
        end

        raise VerifyError, "Signature raw value to cannot be null" if signature.value.nil?
        raise VerifyError, "Components cannot be null"             if signature.components.nil?

        begin
          validate_components message, signature.serialized_components
        rescue Error => ex
          raise VerifyError, ex.message, cause: ex
        end

        return unless no_older_than
        old_sig_msg = "Signature created more than #{no_older_than} seconds ago"
        begin
          raise VerifyError, old_sig_msg if signature.older_than?(no_older_than.to_i)
        rescue Error => ex
          raise VerifyError, ex.message, cause: ex
        end
      end

      def verify_or_fail(key, signature, data)
        return true if key.verify(signature, data)
        raise VerifyError, "Failed to verify message: Invalid signature."
      end
    end
  end
end
