# frozen_string_literal: true

require "digest"

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

      # Verifies an HMAC signature using constant-time comparison.
      #
      # Uses OpenSSL.secure_compare to prevent timing attacks where an
      # attacker could measure response times to guess valid signatures.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      def verify(signature, data)
        OpenSSL.secure_compare(signature, sign(data))
      end

      def private?
        !material.nil?
      end

      def public?
        false
      end

      def inspect
        vars =
          instance_variables
            .reject { |v| v == :@material } # don't leak secret unneccesarily
            .map do |n|
              "#{n}=#{instance_variable_get(n).inspect}"
            end
        oid = Digest::SHA2.hexdigest(object_id.to_s)[48..63]
        "#<%s:0x%s %s>" % [self.class, oid, vars.join(", ")]
      end
    end
  end
end
