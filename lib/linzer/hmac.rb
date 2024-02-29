# frozen_string_literal: true

module Linzer
  module HMAC
    class Key < Linzer::Key
      def validate
        super
        validate_digest
      end

      def sign(data)
        OpenSSL::HMAC.digest(@params[:digest], material, data)
      end

      def verify(signature, data)
        signature == sign(data)
      end
    end
  end
end
