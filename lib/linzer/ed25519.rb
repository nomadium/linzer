# frozen_string_literal: true

require "ed25519"

module Linzer
  module Ed25519
    class Key < Linzer::Key
      def sign(data)
        material.sign(data)
      end

      def verify(signature, data)
        verify_key = material.is_a?(::Ed25519::SigningKey) ? material.verify_key : material
        verify_key.verify(signature, data)
      rescue ::Ed25519::VerifyError
        false
      end
    end
  end
end
