# frozen_string_literal: true

module Linzer
  module RSAPSS
    SALT_LENGTH = 64

    class Key < Linzer::Key
      def validate
        super
        validate_digest
      end

      def sign(data)
        # XXX: should check if the key is usable for signing
        @material.sign(@params[:digest], data, signature_options)
      end

      def verify(signature, data)
        # XXX: should check if the key is usable for verifying
        return true if @material.verify(
          @params[:digest],
          signature,
          data,
          signature_options
        )
        false
      end

      private

      def signature_options
        {
          rsa_padding_mode: "pss",
          rsa_pss_saltlen: @params[:salt_length] || SALT_LENGTH,
          rsa_mgf1_md:   @params[:digest]
        }
      end
    end
  end
end
