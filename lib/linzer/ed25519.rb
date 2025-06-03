# frozen_string_literal: true

module Linzer
  module Ed25519
    class Key < Linzer::Key
      def sign(data)
        validate_signing_key
        material.sign(nil, data)
      end

      def verify(signature, data)
        validate_verify_key
        material.verify(nil, signature, data)
      end

      def public?
        has_pem_public?
      end

      def private?
        has_pem_private?
      end
    end
  end
end
