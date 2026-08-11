# frozen_string_literal: true

module Linzer
  module MLDSA
    # NIST OID for ML-DSA-44 (id-ml-dsa-44), used both by OpenSSL's own
    # PEM/DER encoding and by {wrap_raw_public_key}/{wrap_raw_private_key}
    # below when reconstructing a key from raw FIPS 204 bytes.
    # @return [String]
    OPENSSL_ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17"
    private_constant :OPENSSL_ML_DSA_44_OID

    # ML-DSA-44 (FIPS 204) signing/verification backed directly by OpenSSL
    # 3.5+, with no additional gem dependency.
    #
    # Like Ed25519, ML-DSA is a "pure"/digest-less signature scheme: the
    # RFC 9421 signature base is signed directly, with no prehashing.
    #
    # @note Requires OpenSSL 3.5+ with ML-DSA signature algorithms enabled.
    #   Some distributions ship OpenSSL 3.5+ with these disabled by crypto
    #   policy (see https://github.com/ruby/openssl/issues/1075), so callers
    #   should be prepared for {OpenSSL::PKey::PKeyError} on unsupported
    #   builds even when the OpenSSL version alone looks sufficient.
    #
    # @see Linzer::MLDSA::GemKey for the `ml_dsa`-gem-backed alternative,
    #   which supports all three FIPS 204 parameter sets.
    # @see https://github.com/C2SP/C2SP/blob/httpsig-pq/v0.2.0/httpsig-pq.md
    #   C2SP httpsig-pq: Post-Quantum Algorithms for HTTP Message Signatures
    # @see https://csrc.nist.gov/pubs/fips/204/final FIPS 204
    class OpenSSLKey < Linzer::Key
      # Signs data using the ML-DSA-44 private key.
      #
      # @param data [String] The data to sign (typically the signature base)
      # @return [String] The 2420-byte FIPS 204 ML-DSA-44 signature
      # @raise [SigningError] If this key does not contain private key material
      def sign(data)
        validate_signing_key
        material.sign(nil, data)
      end

      # Verifies a signature using the ML-DSA-44 public key.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      # @raise [VerifyError] If this key does not contain public key material
      def verify(signature, data)
        validate_verify_key
        material.verify(nil, signature, data)
      end

      private

      # @return [Boolean] true if this key contains public key material
      def compute_public?
        has_pem_public?
      end

      # @return [Boolean] true if this key contains private key material
      def compute_private?
        has_pem_private?
      end
    end

    class << self
      # Reconstructs an OpenSSL key from a raw FIPS 204 ML-DSA-44 public key.
      #
      # The `openssl` gem does not yet accept `"ML-DSA-44"` in
      # {OpenSSL::PKey.new_raw_public_key} (there is no upstream issue
      # tracking this as of this writing), so this wraps the raw bytes in a
      # minimal DER SubjectPublicKeyInfo structure that {OpenSSL::PKey.read}
      # does accept. Verified byte-identical to OpenSSL's own
      # `public_to_der` output, across multiple independently generated
      # keys, against OpenSSL 3.5.6.
      #
      # @param raw_public_key [String] 1312-byte raw FIPS 204 public key
      # @return [OpenSSL::PKey::PKey]
      # @api private
      def wrap_raw_public_key(raw_public_key)
        spki = OpenSSL::ASN1::Sequence.new([
          ml_dsa_44_algorithm_identifier,
          OpenSSL::ASN1::BitString.new(raw_public_key)
        ])
        OpenSSL::PKey.read(spki.to_der)
      end

      # Builds an OpenSSL key from a raw FIPS 204 ML-DSA-44 private key.
      #
      # {OpenSSL::PKey.new_raw_private_key} doesn't accept "ML-DSA-44" yet,
      # and unlike the public key, a fixed DER prefix won't work here:
      # OpenSSL's PKCS8 encoding embeds a per-key 32-byte seed alongside the
      # expanded key. This builds the seed-free "expandedKey" alternative of
      # the ML-DSA private key CHOICE instead (an untagged OCTET STRING),
      # which carries no per-key data.
      #
      # @param raw_private_key [String] 2560-byte raw FIPS 204 private key
      # @return [OpenSSL::PKey::PKey]
      # @api private
      def wrap_raw_private_key(raw_private_key)
        expanded_key_choice = OpenSSL::ASN1::OctetString.new(raw_private_key).to_der
        one_asymmetric_key = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer(0),
          ml_dsa_44_algorithm_identifier,
          OpenSSL::ASN1::OctetString.new(expanded_key_choice)
        ])
        OpenSSL::PKey.read(one_asymmetric_key.to_der)
      end

      private

      # @return [OpenSSL::ASN1::Sequence] the ML-DSA-44 AlgorithmIdentifier
      def ml_dsa_44_algorithm_identifier
        OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId(OPENSSL_ML_DSA_44_OID)])
      end
    end
  end
end
