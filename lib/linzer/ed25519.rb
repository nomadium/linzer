# frozen_string_literal: true

module Linzer
  # Ed25519 elliptic curve signature algorithm support.
  #
  # Ed25519 is a modern, high-security signature algorithm that is fast
  # and produces compact signatures. It's recommended for new applications
  # where compatibility with older systems is not required.
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3.6 RFC 9421 Section 3.3.6
  # @see https://ed25519.cr.yp.to/ Ed25519 specification
  module Ed25519
    # Ed25519 signing key implementation.
    #
    # Ed25519 keys can be used for both signing (with private key) and
    # verification (with public key). The algorithm identifier is `ed25519`.
    #
    # @example Generating a new key pair
    #   key = Linzer.generate_ed25519_key("my-key-id")
    #
    # @example Loading from PEM
    #   private_key = Linzer.new_ed25519_key(File.read("ed25519.pem"), "key-1")
    #   public_key = Linzer.new_ed25519_public_key(File.read("ed25519_pub.pem"), "key-1")
    #
    # @see Linzer::Key::Helper#generate_ed25519_key
    # @see Linzer::Key::Helper#new_ed25519_key
    class Key < Linzer::Key
      # Signs data using the Ed25519 private key.
      #
      # @param data [String] The data to sign (typically the signature base)
      # @return [String] The 64-byte Ed25519 signature
      # @raise [SigningError] If this key does not contain private key material
      def sign(data)
        validate_signing_key
        material.sign(nil, data)
      end

      # Verifies a signature using the Ed25519 public key.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      # @raise [VerifyError] If this key does not contain public key material
      def verify(signature, data)
        validate_verify_key
        material.verify(nil, signature, data)
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
    end
  end
end
