# frozen_string_literal: true

module Linzer
  module ECDSA
    class Key < Linzer::Key
      def validate
        super
        validate_digest
      end

      def sign(data)
        material.sign(@params[:digest], data)
      end

      def verify(signature, data)
        material.verify(@params[:digest], signature, data)
      end
    end
  end
end
