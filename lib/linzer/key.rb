# frozen_string_literal: true

module Linzer
  # Abstract base class for cryptographic keys used in HTTP message signatures.
  #
  # This class provides the common interface for all key types supported by Linzer.
  # Do not instantiate this class directly; use one of the concrete subclasses
  # or the key generation/loading helper methods.
  #
  # @abstract Subclass and override {#sign} and {#verify} to implement
  #   a specific cryptographic algorithm.
  #
  # @example Using a concrete key class via helper methods
  #   # Generate a new Ed25519 key pair
  #   key = Linzer.generate_ed25519_key("my-key-id")
  #
  #   # Load an existing RSA-PSS key from PEM
  #   key = Linzer.new_rsa_pss_sha512_key(File.read("private.pem"), "rsa-key")
  #
  # @see Ed25519::Key
  # @see ECDSA::Key
  # @see HMAC::Key
  # @see RSA::Key
  # @see RSAPSS::Key
  # @see JWS::Key
  class Key
    # Creates a new Key instance.
    #
    # @param material [OpenSSL::PKey::PKey, String] The key material.
    #   For asymmetric keys, this is typically an OpenSSL key object.
    #   For HMAC, this is the raw secret bytes.
    # @param params [Hash] Additional key parameters
    # @option params [String] :id The key identifier (keyid) for this key
    # @option params [String] :digest The digest algorithm (e.g., "SHA256", "SHA512")
    #
    # @raise [Error] If key material is nil or invalid
    def initialize(material, params = {})
      @material = material
      @params   = Hash(params).clone.freeze
      validate
      @is_private = compute_private?
      @is_public  = compute_public?
      freeze
    end

    # @return [Object] The underlying key material
    attr_reader :material

    # Returns the key identifier.
    #
    # The key ID is used in the `keyid` parameter of HTTP signatures to
    # identify which key was used for signing.
    #
    # @return [String, nil] The key identifier, or nil if not set
    def key_id
      @params[:id]
    end

    # Signs data using this key.
    #
    # @abstract Subclasses must override this method.
    #
    # @param args [Array] Implementation-specific arguments (typically data to sign)
    # @return [String] The signature bytes
    # @raise [Error] If called on the abstract base class
    # @raise [SigningError] If the key cannot be used for signing
    def sign(*args)
      abstract_error = "Cannot sign data, \"#{self.class}\" is an abstract class."
      raise Error, abstract_error
    end

    # Verifies a signature against data using this key.
    #
    # @abstract Subclasses must override this method.
    #
    # @param args [Array] Implementation-specific arguments (typically signature and data)
    # @return [Boolean] true if the signature is valid, false otherwise
    # @raise [Error] If called on the abstract base class
    # @raise [VerifyError] If the key cannot be used for verification
    def verify(*args)
      abstract_error = "Cannot verify signature, \"#{self.class}\" is an abstract class."
      raise Error, abstract_error
    end

    # Checks if this key can be used for signature verification.
    #
    # @return [Boolean] true if the key contains public key material
    def public?
      @is_public
    end

    # Checks if this key can be used for signing.
    #
    # @return [Boolean] true if the key contains private key material
    def private?
      @is_private
    end

    private

    # Validates that the key has material.
    # @raise [Error] If key material is nil
    def validate
      !material.nil? or raise Error.new "Invalid key. No key material provided."
    end

    # Computes whether the key contains private key material.
    # Override in subclasses where the OpenSSL key object does not
    # respond to +private?+ (e.g. Ed25519, RSA-PSS).
    # @return [Boolean]
    def compute_private?
      material.respond_to?(:private?) ? material.private? : false
    end

    # Computes whether the key contains public key material.
    # Override in subclasses where the OpenSSL key object does not
    # respond to +public?+ (e.g. Ed25519, RSA-PSS).
    # @return [Boolean]
    def compute_public?
      material.respond_to?(:public?) ? material.public? : false
    end

    # Validates that a digest algorithm is configured.
    # @raise [Error] If no digest algorithm is set
    def validate_digest
      no_digest = !@params.key?(:digest) || @params[:digest].nil? || String(@params[:digest]).empty?
      no_digest_error = "Invalid key definition, no digest algorithm was selected."
      raise Error, no_digest_error if no_digest
    end

    # Validates that this key can be used for signing.
    # @raise [SigningError] If the key does not contain private material
    def validate_signing_key
      raise SigningError, "Private key is needed!" unless private?
    end

    # Validates that this key can be used for verification.
    # @raise [VerifyError] If the key does not contain public material
    def validate_verify_key
      raise VerifyError, "Public key is needed!" unless public?
    end

    # Checks if the key material has a PEM-encoded public key.
    # @return [Boolean]
    def has_pem_public?
      material.public_to_pem.match?(/^-----BEGIN PUBLIC KEY-----/)
    end

    # Checks if the key material has a PEM-encoded private key.
    # @return [Boolean]
    def has_pem_private?
      material.private_to_pem.match?(/^-----BEGIN PRIVATE KEY-----/)
    rescue
      false
    end
  end
end
