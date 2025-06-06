# frozen_string_literal: true

module Linzer
  module RSA
    class Key < Linzer::Key
      def validate
        super
        validate_digest
      end

      def sign(data)
        validate_signing_key
        material.sign(@params[:digest], data)
      end

      def verify(signature, data)
        validate_verify_key
        material.verify(@params[:digest], signature, data)
      end
    end
  end
end
