# frozen_string_literal: true

begin
  require "ml_dsa"
rescue LoadError
  raise Linzer::Error, "ml_dsa gem must be installed to use this feature."
end

module Linzer
  module MLDSA
    ALGORITHMS = {
      "ml-dsa-44" => MlDsa::ML_DSA_44,
      "ml-dsa-65" => MlDsa::ML_DSA_65,
      "ml-dsa-87" => MlDsa::ML_DSA_87
    }.freeze

    # ML-DSA signing/verification backed by the `ml_dsa` gem (a C
    # extension bundling the PQClean implementation).
    #
    # Supports all three FIPS 204 parameter sets. Optional: not required
    # by `linzer.rb` itself, and not a runtime dependency of the gemspec,
    # callers who want this backend must add `ml_dsa` to their own
    # Gemfile and `require "linzer/ml_dsa"` themselves, which
    # requires `ml_dsa` in turn.
    #
    # @see Linzer::MLDSA::OpenSSLKey for the dependency-free alternative
    #   backed directly by OpenSSL 3.5+, also supporting all three
    #   parameter sets.
    class GemKey < Linzer::Key
      attr_reader :algorithm

      def initialize(material, params = {})
        @algorithm = String(params.fetch(:algorithm))
        super
      end

      # Validates that the HTTP `alg` parameter matches this key's parameter set.
      #
      # @param parameters [Hash] HTTP signature parameters
      # @return [true] If `alg` is absent or matches this key
      # @raise [VerifyError] If `alg` selects another ML-DSA parameter set
      def validate_signature_parameters(parameters)
        supplied_algorithm = parameters["alg"] || parameters[:alg]
        return true if supplied_algorithm.nil? || supplied_algorithm == algorithm

        raise VerifyError,
          "Signature algorithm #{supplied_algorithm} does not match key algorithm #{algorithm}"
      end

      # Signs an RFC 9421 signature base with an empty FIPS 204 context.
      #
      # @param data [String] Signature base bytes
      # @return [String] Raw FIPS 204 signature bytes
      # @raise [SigningError] If private key material is unavailable
      def sign(data)
        validate_signing_key
        material.sign(data, context: "")
      rescue MlDsa::Error => e
        raise SigningError, e.message, cause: e
      end

      # Verifies an RFC 9421 signature base with an empty FIPS 204 context.
      #
      # @param signature [String] Raw FIPS 204 signature bytes
      # @param data [String] Signature base bytes
      # @return [Boolean] Whether the signature is valid
      # @raise [VerifyError] If public key material is unavailable
      def verify(signature, data)
        validate_verify_key
        return false unless signature.is_a?(String)
        return false unless signature.bytesize == parameter_set.signature_bytes

        verification_material.verify(data, signature, context: "")
      rescue MlDsa::Error, ArgumentError, TypeError
        false
      end

      # @return [Symbol] :ml_dsa -- which backend produced this key
      def backend
        :ml_dsa
      end

      private

      def validate
        super
        expected = ALGORITHMS[algorithm]
        raise Error, "Unsupported ML-DSA algorithm: #{algorithm}" unless expected

        valid_type = material.is_a?(MlDsa::PublicKey) || material.is_a?(MlDsa::SecretKey)
        raise Error, "Invalid ML-DSA key material" unless valid_type

        return if material.param_set == expected

        raise Error,
          "ML-DSA key parameter set #{material.param_set} does not match #{algorithm}"
      end

      def parameter_set
        ALGORITHMS.fetch(algorithm)
      end

      def verification_material
        return material if material.is_a?(MlDsa::PublicKey)
        return material.public_key if material.public_key

        raise VerifyError, "Public key is needed!"
      end

      def compute_private?
        material.is_a?(MlDsa::SecretKey)
      end

      def compute_public?
        material.is_a?(MlDsa::PublicKey) ||
          (material.is_a?(MlDsa::SecretKey) && !material.public_key.nil?)
      end
    end
  end
end
