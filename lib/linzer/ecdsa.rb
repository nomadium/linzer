# frozen_string_literal: true

module Linzer
  # ECDSA (Elliptic Curve Digital Signature Algorithm) support.
  #
  # Supports P-256 (secp256r1/prime256v1) and P-384 (secp384r1) curves
  # with SHA-256 and SHA-384 digests respectively.
  #
  # @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3.3 RFC 9421 Section 3.3.3
  module ECDSA
    # ECDSA signing key implementation.
    #
    # ECDSA keys provide a good balance of security and performance.
    # Supported algorithm identifiers:
    # - `ecdsa-p256-sha256` - NIST P-256 curve with SHA-256
    # - `ecdsa-p384-sha384` - NIST P-384 curve with SHA-384
    #
    # @note ECDSA signatures are converted between DER format (used by OpenSSL)
    #   and the concatenated r||s format required by RFC 9421.
    #
    # @example Generating a P-256 key
    #   key = Linzer.generate_ecdsa_p256_sha256_key("my-key")
    #
    # @example Loading from PEM
    #   key = Linzer.new_ecdsa_p256_sha256_key(File.read("ec_key.pem"), "key-1")
    #
    # @see Linzer::Key::Helper#generate_ecdsa_p256_sha256_key
    # @see Linzer::Key::Helper#generate_ecdsa_p384_sha384_key
    class Key < Linzer::Key
      # @api private
      def validate
        super
        validate_digest
      end

      # Signs data using the ECDSA private key.
      #
      # The signature is returned in concatenated r||s format as required
      # by RFC 9421, not in DER format.
      #
      # @param data [String] The data to sign
      # @return [String] The signature bytes (64 bytes for P-256, 96 for P-384)
      # @raise [SigningError] If this key does not contain private key material
      def sign(data)
        validate_signing_key
        decode_der_signature(material.sign(@params[:digest], data))
      end

      # Verifies a signature using the ECDSA public key.
      #
      # Expects the signature in concatenated r||s format as specified
      # by RFC 9421.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      # @raise [VerifyError] If this key does not contain public key material
      # @raise [Error] If the signature format is invalid
      def verify(signature, data)
        validate_verify_key
        material.verify(@params[:digest], der_signature(signature), data)
      end

      private

      # Mapping of digest algorithms to signature format parameters.
      # hex_length is the total length of r||s in hex characters.
      DIGEST_PARAMS = {
        "SHA256" => {hex_format: "%.64x", hex_length: 64},
        "SHA384" => {hex_format: "%.96x", hex_length: 96}
      }
      private_constant :DIGEST_PARAMS

      # Converts concatenated r||s format to DER for OpenSSL verification.
      # @param sig [String] Signature in r||s format
      # @return [String] DER-encoded signature
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

      # Converts DER-encoded signature to concatenated r||s format.
      # @param der_sig [String] DER-encoded signature from OpenSSL
      # @return [String] Signature in r||s format
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
