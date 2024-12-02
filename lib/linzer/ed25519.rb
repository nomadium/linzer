# frozen_string_literal: true

module Linzer
  module Ed25519
    class Key < Linzer::Key
      def sign(data)
        material.sign(nil, data)
      end

      def verify(signature, data)
        material.verify(nil, signature, data)
      end
    end
  end
end
