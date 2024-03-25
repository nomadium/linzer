# frozen_string_literal: true

module Linzer
  module ECDSA
    class Key < Linzer::Key
      def validate
        super
        validate_digest
      end

      def sign(data)
        decode_der_signature(material.sign(@params[:digest], data))
      end

      def verify(signature, data)
        material.verify(@params[:digest], der_signature(signature), data)
      end

      private

      def der_signature(sig)
        digest = @params[:digest]
        msg = "Cannot verify invalid signature."

        case digest
        when "SHA256"
          raise Linzer::Error.new(msg) if sig.length != 64
          r_bn = OpenSSL::BN.new(sig[0..31].unpack1("H64").to_i(16))
          s_bn = OpenSSL::BN.new(sig[32..63].unpack1("H64").to_i(16))
        when "SHA384"
          raise Linzer::Error.new(msg) if sig.length != 96
          r_bn = OpenSSL::BN.new(sig[0..47].unpack1("H96").to_i(16))
          s_bn = OpenSSL::BN.new(sig[48..95].unpack1("H96").to_i(16))
        else
          msg = "Cannot verify signature, unsupported digest algorithm: '%s'" % digest
          raise Linzer::Error.new(msg)
        end

        r = OpenSSL::ASN1::Integer(r_bn)
        s = OpenSSL::ASN1::Integer(s_bn)

        seq = OpenSSL::ASN1::Sequence.new([r, s])
        seq.to_der
      end

      def decode_der_signature(der_sig)
        digest = @params[:digest]
        msg = "Unsupported digest algorithm: '%s'" % digest
        OpenSSL::ASN1
          .decode(der_sig)
          .value
          .map do |n|
            case digest
            when "SHA256" then "%.64x" % n.value
            when "SHA384" then "%.96x" % n.value
            else raise Linzer::Error.new(msg)
            end
          end
          .map { |s| [s].pack("H#{s.length}") }
          .reduce(:<<)
          .encode(Encoding::ASCII_8BIT)
      end
    end
  end
end
