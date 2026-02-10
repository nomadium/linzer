# frozen_string_literal: true

module Linzer
  # RSA PKCS#1 v1.5 signature algorithm support.
  #
  # This implements the traditional RSA signature scheme using PKCS#1 v1.5
  # padding. For new applications, consider using RSA-PSS ({RSAPSS}) instead,
  # which provides better security properties.
  #
  # @note RSA-PSS is recommended over PKCS#1 v1.5 for new applications.
  #
  # @see RSAPSS RSA-PSS (recommended)
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3.2 RFC 9421 Section 3.3.2
  module RSA
    # RSA PKCS#1 v1.5 signing key implementation.
    #
    # Uses the `rsa-v1_5-sha256` algorithm identifier.
    #
    # @example Generating a new key
    #   key = Linzer.generate_rsa_v1_5_sha256_key(2048, "my-rsa-key")
    #
    # @example Loading from PEM
    #   key = Linzer.new_rsa_v1_5_sha256_key(File.read("rsa.pem"), "key-1")
    #
    # @see Linzer::Key::Helper#generate_rsa_v1_5_sha256_key
    # @see Linzer::Key::Helper#new_rsa_v1_5_sha256_key
    class Key < Linzer::Key
      # @api private
      def validate
        super
        validate_digest
      end

      # Signs data using RSA PKCS#1 v1.5.
      #
      # @param data [String] The data to sign
      # @return [String] The RSA signature
      # @raise [SigningError] If this key does not contain private key material
      def sign(data)
        validate_signing_key
        material.sign(@params[:digest], data)
      end

      # Verifies an RSA PKCS#1 v1.5 signature.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      # @raise [VerifyError] If this key does not contain public key material
      def verify(signature, data)
        validate_verify_key
        material.verify(@params[:digest], signature, data)
      end
    end
  end
end
