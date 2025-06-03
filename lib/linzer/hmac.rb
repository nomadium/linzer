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

      def verify(signature, data)
        signature == sign(data)
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
