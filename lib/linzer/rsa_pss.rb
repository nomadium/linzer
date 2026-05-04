# frozen_string_literal: true

module Linzer
  # RSA-PSS (RSASSA-PSS) signature algorithm support.
  #
  # RSA-PSS is the recommended RSA signature scheme, providing better
  # security properties than the older PKCS#1 v1.5 scheme. It uses
  # probabilistic padding which makes signatures non-deterministic.
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3.1 RFC 9421 Section 3.3.1
  # @see https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1 RFC 8017 RSASSA-PSS
  module RSAPSS
    # Default salt length for PSS padding (64 bytes).
    # @return [Integer]
    SALT_LENGTH = 64

    # RSA-PSS signing key implementation.
    #
    # Uses the `rsa-pss-sha512` algorithm identifier with a 64-byte salt.
    #
    # @note RSA-PSS signatures are non-deterministic due to random salt.
    #   The same data signed twice will produce different signatures,
    #   but both will verify successfully.
    #
    # @example Generating a new key
    #   key = Linzer.generate_rsa_pss_sha512_key(2048, "my-key")
    #
    # @example Loading from PEM
    #   key = Linzer.new_rsa_pss_sha512_key(File.read("rsa_pss.pem"), "key-1")
    #
    # @see Linzer::Key::Helper#generate_rsa_pss_sha512_key
    # @see Linzer::Key::Helper#new_rsa_pss_sha512_key
    class Key < Linzer::Key
      # @api private
      def validate
        super
        validate_digest
      end

      # Signs data using RSA-PSS.
      #
      # @param data [String] The data to sign
      # @return [String] The RSA-PSS signature
      # @raise [SigningError] If this key does not contain private key material
      #
      # @note The signature is non-deterministic due to random PSS salt.
      def sign(data)
        validate_signing_key
        material.sign(@params[:digest], data, signature_options)
      end

      # Verifies an RSA-PSS signature.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      # @raise [VerifyError] If this key does not contain public key material
      def verify(signature, data)
        validate_verify_key
        material.verify(
          @params[:digest],
          signature,
          data,
          signature_options
        )
      end

      private

      # @return [Boolean] true if this key contains public key material
      def compute_public?
        has_pem_public?
      end

      # @return [Boolean] true if this key contains private key material
      def compute_private?
        has_pem_private?
      end

      # Returns OpenSSL options for PSS signature operations.
      # @return [Hash] OpenSSL signature options
      def signature_options
        {
          rsa_padding_mode: "pss",
          rsa_pss_saltlen: @params[:salt_length] || SALT_LENGTH,
          rsa_mgf1_md:   @params[:digest]
        }
      end
    end
  end
end
