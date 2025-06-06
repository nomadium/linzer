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
        validate_signing_key
        material.sign(@params[:digest], data, signature_options)
      end

      def verify(signature, data)
        validate_verify_key
        material.verify(
          @params[:digest],
          signature,
          data,
          signature_options
        )
      end

      def public?
        has_pem_public?
      end

      def private?
        has_pem_private?
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
