# frozen_string_literal: true

require "jwt"
require "jwt/eddsa"
require "ed25519"

module Linzer
  # JSON Web Signature (JWS) compatible key support.
  #
  # This module provides integration with the jwt gem for working with
  # JWK (JSON Web Key) format keys. It enables interoperability with
  # systems using JWS/JWT standards.
  #
  # Currently supports:
  # - EdDSA (Ed25519)
  #
  # @note This module requires the `jwt` and `ed25519` gems.
  #
  # @example Generating a JWS-compatible EdDSA key
  #   key = Linzer.generate_jws_key(algorithm: "EdDSA")
  #
  # @example Importing from JWK format
  #   jwk = {
  #     "kty" => "OKP",
  #     "crv" => "Ed25519",
  #     "x" => "...",
  #     "d" => "..."  # private key component (optional)
  #   }
  #   key = Linzer.jwk_import(jwk)
  #
  # @see https://www.rfc-editor.org/rfc/rfc7517 RFC 7517 - JSON Web Key (JWK)
  # @see https://www.rfc-editor.org/rfc/rfc8037 RFC 8037 - EdDSA for JWS/JWK
  module JWS
    # Imports a key from JWK (JSON Web Key) format.
    #
    # @param key [Hash] The JWK as a Hash with string keys
    # @param params [Hash] Additional key parameters
    # @option params [String] :id Key identifier (overrides JWK "kid" if present)
    # @return [JWS::Key] The imported key
    # @raise [Error] If the JWK format is invalid or algorithm unsupported
    #
    # @example
    #   jwk = JSON.parse(File.read("key.jwk"))
    #   key = Linzer::JWS.jwk_import(jwk, id: "my-key-id")
    def jwk_import(key, params = {})
      material = JWT::JWK.import(key)
      Linzer::JWS::Key.new(material, params)
    end
    module_function :jwk_import

    # Generates a new JWS-compatible key pair.
    #
    # @param algorithm [String] The JWS algorithm identifier.
    #   Currently only "EdDSA" is supported.
    # @return [JWS::Key] A new key pair
    # @raise [Error] If the algorithm is not supported
    #
    # @example
    #   key = Linzer::JWS.generate_key(algorithm: "EdDSA")
    def generate_key(algorithm:)
      case String(algorithm)
      when "EdDSA"
        ed25519_keypair = ::Ed25519::SigningKey.generate
        material = JWT::JWK.new(ed25519_keypair)
        Linzer::JWS::Key.new(material)
      else
        err_msg = "Algorithm '#{algorithm}' is unsupported or not implemented yet."
        raise Linzer::Error, err_msg
      end
    end
    module_function :generate_key

    # JWS-compatible signing key implementation.
    #
    # Wraps a JWT::JWK key object to provide the Linzer Key interface.
    # This enables using JWK-format keys with HTTP Message Signatures.
    #
    # @see Linzer::Key::Helper#generate_jws_key
    # @see Linzer::Key::Helper#jwk_import
    class Key < Linzer::Key
      # Signs data using the JWS key.
      #
      # @param data [String] The data to sign
      # @return [String] The signature bytes
      # @raise [SigningError] If this key cannot be used for signing
      def sign(data)
        validate_signing_key
        algo = resolve_algorithm
        algo.sign(data: data, signing_key: signing_key)
      end

      # Verifies a signature using the JWS key.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if valid, false otherwise
      # @raise [VerifyError] If this key cannot be used for verification
      def verify(signature, data)
        validate_verify_key
        algo = resolve_algorithm
        algo.verify(data: data, signature: signature, verification_key: verify_key)
      end

      # @return [Boolean] true if this key can verify signatures
      def public?
        !!verify_key
      end

      # @return [Boolean] true if this key can create signatures
      def private?
        !!signing_key
      end

      private

      # Resolves the appropriate JWT algorithm implementation.
      # @return [JWT::JWA::SigningAlgorithm] The algorithm implementation
      # @raise [Error] If the algorithm cannot be determined
      def resolve_algorithm
        case
        when material.verify_key.is_a?(::Ed25519::VerifyKey)
          JWT::JWA.resolve("EdDSA")
        else
          raise Linzer::Error, "Unknown/unsupported algorithm"
        end
      end

      # @return [Ed25519::VerifyKey, nil] The verification key
      def verify_key
        material.verify_key
      end

      # @return [Ed25519::SigningKey, nil] The signing key
      def signing_key
        material.signing_key
      end
    end
  end
end
