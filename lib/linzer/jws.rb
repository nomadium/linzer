# frozen_string_literal: true

require "jwt"
require "jwt/eddsa"
require "ed25519"

module Linzer
  module JWS
    def jwk_import(key, params = {})
      material = JWT::JWK.import(key)
      Linzer::JWS::Key.new(material, params)
    end
    module_function :jwk_import

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

    class Key < Linzer::Key
      def sign(data)
        validate_signing_key
        algo = resolve_algorithm
        algo.sign(data: data, signing_key: signing_key)
      end

      def verify(signature, data)
        validate_verify_key
        algo = resolve_algorithm
        algo.verify(data: data, signature: signature, verification_key: verify_key)
      end

      def public?
        !!verify_key
      end

      private

      def resolve_algorithm
        case
        when material.verify_key.is_a?(::Ed25519::VerifyKey)
          JWT::JWA.resolve("EdDSA")
        else
          raise Linzer::Error, "Unknown/unsupported algorithm"
        end
      end

      def verify_key
        material.verify_key
      end

      def signing_key
        material.signing_key
      end
    end
  end
end
