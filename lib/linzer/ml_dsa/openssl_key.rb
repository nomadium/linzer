# frozen_string_literal: true

module Linzer
  module MLDSA
    # NIST OIDs for ML-DSA (id-ml-dsa-44/65/87), used both by OpenSSL's own
    # PEM/DER encoding and by {wrap_raw_public_key}/{wrap_raw_private_key}
    # below when reconstructing a key from raw FIPS 204 bytes. Verified
    # against real OpenSSL 3.5+ output (decoded from a freshly generated
    # key's own `public_to_der`), not taken from documentation alone.
    # @return [Hash{String => String}]
    OPENSSL_OIDS = {
      "ml-dsa-44" => "2.16.840.1.101.3.4.3.17",
      "ml-dsa-65" => "2.16.840.1.101.3.4.3.18",
      "ml-dsa-87" => "2.16.840.1.101.3.4.3.19"
    }.freeze
    private_constant :OPENSSL_OIDS

    # Linzer algorithm identifiers (lowercase, e.g. "ml-dsa-44") that this
    # OpenSSL-backed implementation actually has construction/OID support
    # for today. {openssl_supported?} treats anything outside this set as
    # unsupported without ever asking OpenSSL about it.
    # @return [Array<String>]
    IMPLEMENTED_ALGORITHMS = %w[ml-dsa-44 ml-dsa-65 ml-dsa-87].freeze
    private_constant :IMPLEMENTED_ALGORITHMS

    # FIPS 204 raw public-key sizes per parameter set, used to sniff raw
    # key material in {deserialize_raw_or_encoded_key} the same way
    # {GemKey} does for the gem backend.
    # @return [Hash{String => Integer}]
    RAW_PUBLIC_KEY_BYTES = {
      "ml-dsa-44" => 1312,
      "ml-dsa-65" => 1952,
      "ml-dsa-87" => 2592
    }.freeze
    private_constant :RAW_PUBLIC_KEY_BYTES

    # FIPS 204 raw (expanded, seed-free) private-key sizes per parameter set.
    # @return [Hash{String => Integer}]
    RAW_PRIVATE_KEY_BYTES = {
      "ml-dsa-44" => 2560,
      "ml-dsa-65" => 4032,
      "ml-dsa-87" => 4896
    }.freeze
    private_constant :RAW_PRIVATE_KEY_BYTES

    # ML-DSA (FIPS 204) signing/verification backed directly by OpenSSL
    # 3.5+, with no additional gem dependency. Supports all three
    # parameter sets (ML-DSA-44/65/87).
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
    # @see Linzer::MLDSA::GemKey for the `ml_dsa`-gem-backed alternative
    # @see https://github.com/C2SP/C2SP/blob/httpsig-pq/v0.2.0/httpsig-pq.md
    #   C2SP httpsig-pq: Post-Quantum Algorithms for HTTP Message Signatures
    # @see https://csrc.nist.gov/pubs/fips/204/final FIPS 204
    class OpenSSLKey < Linzer::Key
      # @return [String] The FIPS 204 parameter set this key was
      #   constructed for, e.g. `"ml-dsa-44"`
      attr_reader :algorithm

      # @param material [OpenSSL::PKey::PKey] The underlying OpenSSL key
      # @param params [Hash] Additional key parameters
      # @option params [String] :algorithm Required. One of
      #   `"ml-dsa-44"`/`"ml-dsa-65"`/`"ml-dsa-87"`
      # @option params [String] :id The key identifier (keyid)
      def initialize(material, params = {})
        @algorithm = String(params.fetch(:algorithm))
        super
      end

      # Validates that the HTTP `alg` parameter matches this key's algorithm.
      #
      # @param parameters [Hash] HTTP signature parameters
      # @return [true] If `alg` is absent or matches this key
      # @raise [VerifyError] If `alg` selects a different algorithm
      def validate_signature_parameters(parameters)
        supplied_algorithm = parameters["alg"] || parameters[:alg]
        return true if supplied_algorithm.nil? || supplied_algorithm == algorithm

        raise VerifyError,
          "Signature algorithm #{supplied_algorithm} does not match key algorithm #{algorithm}"
      end

      # Signs data using the ML-DSA private key.
      #
      # @param data [String] The data to sign (typically the signature base)
      # @return [String] The FIPS 204 signature
      # @raise [SigningError] If this key does not contain private key material
      def sign(data)
        validate_signing_key
        material.sign(nil, data)
      end

      # Verifies a signature using the ML-DSA public key.
      #
      # @param signature [String] The signature bytes to verify
      # @param data [String] The data that was signed
      # @return [Boolean] true if the signature is valid, false otherwise
      # @raise [VerifyError] If this key does not contain public key material
      def verify(signature, data)
        validate_verify_key
        material.verify(nil, signature, data)
      end

      # @return [Symbol] :openssl -- which backend produced this key
      def backend
        :openssl
      end

      private

      # Cross-checks the underlying OpenSSL key material against the
      # claimed {algorithm}. Only actually able to catch a mismatch when
      # `material` came in as PEM/DER (via {OpenSSL::PKey.read}) for a
      # *different* ML-DSA parameter set than requested, material built
      # via {Linzer::MLDSA.deserialize_raw_or_encoded_key}'s raw-byte path
      # or `OpenSSL::PKey.generate_key(algorithm.upcase)` is already
      # guaranteed consistent by construction, so this is a no-op for
      # those (cheap: `public_to_der` on an already-parsed key, no network
      # or extra crypto). Best-effort: if the material's own OID can't be
      # determined at all, doesn't fail the whole key over it, something
      # downstream (sign/verify) will surface a real problem regardless.
      # @raise [Error] If key material is nil, or its actual algorithm
      #   doesn't match {algorithm}
      def validate
        super
        expected_oid = OPENSSL_OIDS.fetch(algorithm) { raise Error, "Unsupported ML-DSA algorithm: #{algorithm}" }
        actual_oid = material_openssl_oid
        return if actual_oid.nil? || actual_oid == expected_oid

        raise Error, "ML-DSA key material (#{actual_oid}) does not match algorithm #{algorithm}"
      end

      # @return [String, nil] The dotted OID of `material`'s own
      #   AlgorithmIdentifier, or nil if it can't be determined
      def material_openssl_oid
        spki = OpenSSL::ASN1.decode(material.public_to_der)
        spki.value[0].value[0].oid
      rescue OpenSSL::ASN1::ASN1Error, OpenSSL::PKey::PKeyError
        nil
      end

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
      # Checks whether this OpenSSL build can actually perform ML-DSA
      # signing/verification for the given algorithm.
      #
      # Returns true only when the algorithm is *both* something this
      # OpenSSL-backed implementation has actually implemented (see
      # {IMPLEMENTED_ALGORITHMS}) *and* something the underlying OpenSSL
      # library itself supports. This is needed mostly because a
      # version-number check alone isn't reliable and some distributions ship
      # OpenSSL 3.5+ with ML-DSA disabled by crypto policy (see
      # https://github.com/ruby/openssl/issues/1075), so this actually
      # attempts a throwaway key generation rather than inspecting
      # `OpenSSL::OPENSSL_VERSION`.
      #
      # Memoized per algorithm after the first check, so repeated calls are
      # free. Unknown or not-yet-implemented algorithm identifiers return
      # `false` rather than raising.
      #
      # @param algorithm [String] Linzer's lowercase algorithm identifier,
      #   e.g. `"ml-dsa-44"`
      # @return [Boolean]
      def openssl_supported?(algorithm)
        cache = (@openssl_supported ||= {})
        return cache[algorithm] if cache.key?(algorithm)

        cache[algorithm] =
          if IMPLEMENTED_ALGORITHMS.include?(algorithm)
            begin
              OpenSSL::PKey.generate_key(algorithm.upcase)
              true
            rescue OpenSSL::PKey::PKeyError
              false
            end
          else
            false
          end
      end

      # Builds an OpenSSL key from ML-DSA material of unknown shape: raw
      # FIPS 204 bytes for `algorithm` (sniffed by exact byte length, the
      # same approach {Linzer::MLDSA::GemKey} uses for the gem backend) or
      # an OpenSSL-encoded PEM/DER key, handled as a fallback. Sniffing is
      # scoped to `algorithm`'s own raw sizes, not all three parameter
      # sets' sizes at once, material sized for a *different* parameter
      # set than requested falls through to the `OpenSSL::PKey.read`
      # fallback and fails there (raw bytes aren't valid PEM/DER), rather
      # than silently being accepted and mislabeled.
      #
      # @param material [String] Raw FIPS 204 bytes, or a PEM/DER-encoded key
      # @param algorithm [String] Linzer's lowercase algorithm identifier,
      #   e.g. `"ml-dsa-44"`
      # @return [OpenSSL::PKey::PKey]
      # @api private
      def deserialize_raw_or_encoded_key(material, algorithm)
        case material.bytesize
        when RAW_PUBLIC_KEY_BYTES.fetch(algorithm)
          wrap_raw_public_key(material, algorithm)
        when RAW_PRIVATE_KEY_BYTES.fetch(algorithm)
          wrap_raw_private_key(material, algorithm)
        else
          OpenSSL::PKey.read(material)
        end
      end

      private

      # Reconstructs an OpenSSL key from a raw FIPS 204 ML-DSA public key.
      #
      # The `openssl` gem does not yet accept ML-DSA algorithm names in
      # {OpenSSL::PKey.new_raw_public_key} (there is no upstream issue
      # tracking this as of this writing), so this wraps the raw bytes in a
      # minimal DER SubjectPublicKeyInfo structure that {OpenSSL::PKey.read}
      # does accept. Verified byte-identical to OpenSSL's own
      # `public_to_der` output for ml-dsa-44; for ml-dsa-65/87, verified
      # via a full raw-bytes-in/sign/verify round trip instead (a
      # byte-level mismatch would fail that too). Tested against OpenSSL 3.5+
      # in both cases.
      #
      # @param raw_public_key [String] Raw FIPS 204 public key bytes
      # @param algorithm [String] Linzer's lowercase algorithm identifier
      # @return [OpenSSL::PKey::PKey]
      def wrap_raw_public_key(raw_public_key, algorithm)
        spki = OpenSSL::ASN1::Sequence.new([
          ml_dsa_algorithm_identifier(algorithm),
          OpenSSL::ASN1::BitString.new(raw_public_key)
        ])
        OpenSSL::PKey.read(spki.to_der)
      end

      # Builds an OpenSSL key from a raw FIPS 204 ML-DSA private key.
      #
      # {OpenSSL::PKey.new_raw_private_key} doesn't accept ML-DSA algorithm
      # names yet, and unlike the public key, a fixed DER prefix won't work
      # here: OpenSSL's PKCS8 encoding embeds a per-key 32-byte seed
      # alongside the expanded key. This builds the seed-free "expandedKey"
      # alternative of the ML-DSA private key CHOICE instead (an untagged
      # OCTET STRING), which carries no per-key data.
      #
      # @param raw_private_key [String] Raw FIPS 204 private key bytes
      # @param algorithm [String] Linzer's lowercase algorithm identifier
      # @return [OpenSSL::PKey::PKey]
      def wrap_raw_private_key(raw_private_key, algorithm)
        expanded_key_choice = OpenSSL::ASN1::OctetString.new(raw_private_key).to_der
        one_asymmetric_key = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer(0),
          ml_dsa_algorithm_identifier(algorithm),
          OpenSSL::ASN1::OctetString.new(expanded_key_choice)
        ])
        OpenSSL::PKey.read(one_asymmetric_key.to_der)
      end

      # @param algorithm [String] Linzer's lowercase algorithm identifier
      # @return [OpenSSL::ASN1::Sequence] the ML-DSA AlgorithmIdentifier
      def ml_dsa_algorithm_identifier(algorithm)
        OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId(OPENSSL_OIDS.fetch(algorithm))])
      end
    end
  end
end
