# frozen_string_literal: true

require "jwt"
require "jwt/eddsa"

module Linzer
  module JWA
    def jwk_import(key, params = {})
      material = JWT::JWK.import(key)
      Linzer::JWA::Key.new(material, params)
    end
    module_function :jwk_import

    class Key < Linzer::Key
      def sign(data)
        raise Linzer::SigningError, "Unimplemented algorithm"
      end

      def verify(signature, data)
        algo = resolve_algorithm
        algo.verify(data: data, signature: signature, verification_key: verify_key)
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
    end
  end
end
