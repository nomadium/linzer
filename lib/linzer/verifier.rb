# frozen_string_literal: true

module Linzer
  # Handles HTTP message signature verification according to RFC 9421.
  #
  # This module verifies that a signature on an HTTP message is valid by:
  # 1. Reconstructing the signature base from the message and signature parameters
  # 2. Verifying the signature using the provided public key
  #
  # @example Direct usage (prefer Linzer.verify for convenience)
  #   signature = Linzer::Signature.build(signature_headers)
  #   message = Linzer::Message.new(request)
  #   Linzer::Verifier.verify(pubkey, message, signature)
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2 RFC 9421 Section 3.2
  module Verifier
    class << self
      include Common

      # Verifies an HTTP message signature.
      #
      # Verification succeeds if:
      # - All covered components exist in the message
      # - The signature base matches what was signed
      # - The cryptographic signature is valid for the public key
      # - The signature has not expired (if `expires` parameter is present)
      # - The signature is not older than `no_older_than` (if specified)
      #
      # @param key [Linzer::Key] The public key to verify with. Must respond to
      #   `#verify` and should contain public key material.
      # @param message [Linzer::Message] The HTTP message to verify
      # @param signature [Linzer::Signature] The signature to verify. Typically
      #   built from the `signature` and `signature-input` headers using
      #   {Signature.build}.
      # @param no_older_than [Integer, nil] Maximum age in seconds. If the
      #   signature's `created` parameter is older than this, verification fails.
      #   This helps mitigate replay attacks. See RFC 9421 Section 7.2.2.
      #
      # @return [true] Returns true if verification succeeds
      #
      # @raise [VerifyError] If the message is nil
      # @raise [VerifyError] If the key is nil
      # @raise [VerifyError] If the signature is nil or invalid
      # @raise [VerifyError] If required components are missing from the message
      # @raise [VerifyError] If the signature is too old (when no_older_than is set)
      # @raise [VerifyError] If the cryptographic verification fails
      #
      # @example Basic verification
      #   Linzer::Verifier.verify(pubkey, message, signature)
      #   # => true (or raises VerifyError)
      #
      # @example With age validation (5 minute window)
      #   Linzer::Verifier.verify(pubkey, message, signature, no_older_than: 300)
      #
      # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2 Signature Replay
      def verify(key, message, signature, no_older_than: nil)
        validate message, key, signature, no_older_than: no_older_than

        parameters = signature.parameters
        serialized_components = signature.serialized_components

        # Build fresh field_ids for signature_base (validate already
        # consumed its own set, which may have been mutated by adapters).
        field_ids = signature.field_ids

        signature_base = signature_base(message, serialized_components, parameters,
                                        field_ids: field_ids)

        verify_or_fail key, signature.value, signature_base
      end

      private

      # Validates all verification inputs before attempting verification.
      # @raise [VerifyError] If any input is invalid or signature is too old
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
          validate_components message, signature.serialized_components,
                             field_ids: signature.field_ids
        rescue Error => ex
          raise VerifyError, ex.message, cause: ex
        end

        begin
          exp_sig_msg = "Signature has expired or is invalid"
          raise VerifyError, exp_sig_msg if signature.expired?
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

      # Performs cryptographic verification and raises on failure.
      # @return [true] If verification succeeds
      # @raise [VerifyError] If verification fails
      def verify_or_fail(key, signature, data)
        return true if key.verify(signature, data)
        raise VerifyError, "Failed to verify message: Invalid signature."
      end
    end
  end
end
