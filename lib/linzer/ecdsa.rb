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

      DIGEST_PARAMS = {
        "SHA256" => {hex_format: "%.64x", hex_length: 64},
        "SHA384" => {hex_format: "%.96x", hex_length: 96}
      }
      private_constant :DIGEST_PARAMS

      def der_signature(sig)
        digest = @params[:digest]
        msg = "Cannot verify invalid signature."
        raise Linzer::Error.new(msg) unless DIGEST_PARAMS.key?(digest)
        digest_params = DIGEST_PARAMS[digest]

        l   = digest_params[:hex_length]
        raise Linzer::Error.new(msg) if sig.length != l
        h   = l / 2
        fmt = "H#{l}"

        r_bn = OpenSSL::BN.new(sig[0..(h - 1)].unpack1(fmt).to_i(16))
        s_bn = OpenSSL::BN.new(sig[h..(l - 1)].unpack1(fmt).to_i(16))

        r = OpenSSL::ASN1::Integer(r_bn)
        s = OpenSSL::ASN1::Integer(s_bn)

        seq = OpenSSL::ASN1::Sequence.new([r, s])
        seq.to_der
      end

      def decode_der_signature(der_sig)
        digest = @params[:digest]
        msg = "Unsupported digest algorithm: '%s'" % digest
        raise Linzer::Error.new(msg) unless DIGEST_PARAMS.key?(digest)
        digest_params = DIGEST_PARAMS[digest]
        fmt = "H#{digest_params[:hex_length]}"

        OpenSSL::ASN1
          .decode(der_sig)
          .value
          .map { |bn| digest_params[:hex_format] % bn.value }
          .map { |hex| [hex].pack(fmt) }
          .reduce(:<<)
          .encode(Encoding::ASCII_8BIT)
      end
    end
  end
end
