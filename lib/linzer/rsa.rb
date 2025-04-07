# frozen_string_literal: true

module Linzer
  module RSA
    class Key < Linzer::Key
      def validate
        super
        validate_digest
      end

      def sign(data)
        # XXX: should check if the key is usable for signing
        @material.sign(@params[:digest], data)
      end

      def verify(signature, data)
        # XXX: should check if the key is usable for verifying
        return true if @material.verify(@params[:digest], signature, data)
        false
      end
    end
  end
end
