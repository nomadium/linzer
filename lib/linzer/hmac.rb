# frozen_string_literal: true

require "digest"

module Linzer
  # HMAC (Hash-based Message Authentication Code) symmetric signing support.
  #
  # HMAC uses a shared secret key for both signing and verification.
  # This is useful when both parties can securely share a secret.
  #
  # @note HMAC keys are symmetric - the same key is used for signing and
  #   verification. Keep the key material secret!
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3.5 RFC 9421 Section 3.3.5
  module HMAC
    # HMAC signing key implementation.
    #
    # HMAC-SHA256 is the primary supported algorithm, using the
    # `hmac-sha256` algorithm identifier.
    #
    # @example Generating a new key
    #   key = Linzer.generate_hmac_sha256_key("shared-key")
    #
    # @example Using existing secret material
    #   secret = Base64.decode64(ENV["SIGNING_SECRET"])
    #   key = Linzer.new_hmac_sha256_key(secret, "api-key")
    #
    # @see Linzer::Key::Helper#generate_hmac_sha256_key
    # @see Linzer::Key::Helper#new_hmac_sha256_key
    class Key < Linzer::Key
      # @api private
      def validate
        super
        validate_digest
      end

      # Signs data using HMAC.
      #
      # @param data [String] The data to sign
      # @return [String] The HMAC digest (32 bytes for SHA-256)
      def sign(data)
        OpenSSL::HMAC.digest(@params[:digest], material, data)
      end

      # Verifies an HMAC signature using constant-time comparison.
      #
      # Uses OpenSSL.secure_compare to prevent timing attacks where an
      # attacker could measure response times to guess valid signatures.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      def verify(signature, data)
        OpenSSL.secure_compare(signature, sign(data))
      end

      # HMAC keys can always sign (they contain the secret).
      # @return [Boolean] true if key material is present
      def private?
        !material.nil?
      end

      # HMAC keys are symmetric, not public/private.
      # @return [Boolean] always false for HMAC keys
      def public?
        false
      end

      # Returns a safe string representation that doesn't leak the secret.
      #
      # The key material is intentionally excluded from the output to prevent
      # accidental exposure in logs or error messages.
      #
      # @return [String] A string representation without the secret key
      def inspect
        vars =
          instance_variables
            .reject { |v| v == :@material } # don't leak secret unneccesarily
            .map do |n|
              "#{n}=#{instance_variable_get(n).inspect}"
            end
        oid = Digest::SHA2.hexdigest(object_id.to_s)[48..63]
        "#<%s:0x%s %s>" % [self.class, oid, vars.join(", ")]
      end
    end
  end
end
