# frozen_string_literal: true

module Linzer
  class Key
    # Helper methods for generating and loading cryptographic keys.
    #
    # These methods provide convenient factory functions for creating
    # {Linzer::Key} instances for various algorithms. They are mixed into
    # the {Linzer} module and can be called directly.
    #
    # @example Generating keys
    #   ed25519_key = Linzer.generate_ed25519_key("my-key")
    #   hmac_key = Linzer.generate_hmac_sha256_key("hmac-key")
    #   ecdsa_key = Linzer.generate_ecdsa_p256_sha256_key("ecdsa-key")
    #
    # @example Loading keys from PEM
    #   key = Linzer.new_ed25519_key(File.read("private.pem"), "my-key")
    #   pubkey = Linzer.new_ed25519_public_key(File.read("public.pem"), "my-key")
    #
    # @see Key
    module Helper
      # Generates a new RSA-PSS key pair with SHA-512 digest.
      #
      # RSA-PSS (RSASSA-PSS) is the recommended RSA signature scheme.
      # Uses the `rsa-pss-sha512` algorithm identifier.
      #
      # @param size [Integer] Key size in bits (ignored, uses OpenSSL default)
      # @param key_id [String, nil] Optional key identifier
      # @return [RSAPSS::Key] A new RSA-PSS key pair
      #
      # @example
      #   key = Linzer.generate_rsa_pss_sha512_key(2048, "my-rsa-key")
      def generate_rsa_pss_sha512_key(size, key_id = nil)
        material = OpenSSL::PKey.generate_key("RSASSA-PSS")
        Linzer::RSAPSS::Key.new(material, id: key_id, digest: "SHA512")
      end

      # Loads an RSA-PSS key from PEM-encoded material.
      #
      # Can load either a private key (for signing) or public key (for verification).
      #
      # @param material [String] PEM-encoded RSA key
      # @param key_id [String, nil] Optional key identifier
      # @return [RSAPSS::Key] The loaded key
      #
      # @example Loading a private key
      #   key = Linzer.new_rsa_pss_sha512_key(File.read("private.pem"), "my-key")
      #
      # @example Loading a public key
      #   pubkey = Linzer.new_rsa_pss_sha512_key(File.read("public.pem"), "my-key")
      def new_rsa_pss_sha512_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::RSAPSS::Key.new(key, id: key_id, digest: "SHA512")
      end

      # Loads an RSA-PSS public key from PEM-encoded material.
      #
      # @deprecated Use {#new_rsa_pss_sha512_key} instead, which handles both
      #   public and private keys.
      # @param material [String] PEM-encoded RSA public key
      # @param key_id [String, nil] Optional key identifier
      # @return [RSAPSS::Key] The loaded public key
      def new_rsa_pss_sha512_public_key(material, key_id = nil)
        key = OpenSSL::PKey::RSA.new(material)
        Linzer::RSAPSS::Key.new(key, id: key_id, digest: "SHA512")
      end

      # Generates a new RSA PKCS#1 v1.5 key pair with SHA-256 digest.
      #
      # @note RSA-PSS is preferred for new applications. Use this only for
      #   compatibility with systems requiring PKCS#1 v1.5.
      #
      # Uses the `rsa-v1_5-sha256` algorithm identifier.
      #
      # @param size [Integer] Key size in bits (e.g., 2048, 4096)
      # @param key_id [String, nil] Optional key identifier
      # @return [RSA::Key] A new RSA key pair
      #
      # @example
      #   key = Linzer.generate_rsa_v1_5_sha256_key(2048, "legacy-rsa")
      def generate_rsa_v1_5_sha256_key(size, key_id = nil)
        material = OpenSSL::PKey::RSA.generate(size)
        Linzer::RSA::Key.new(material, id: key_id, digest: "SHA256")
      end

      # Loads an RSA PKCS#1 v1.5 key from PEM-encoded material.
      #
      # @param material [String] PEM-encoded RSA key
      # @param key_id [String, nil] Optional key identifier
      # @return [RSA::Key] The loaded key
      def new_rsa_v1_5_sha256_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::RSA::Key.new(key, id: key_id, digest: "SHA256")
      end

      # Loads an RSA PKCS#1 v1.5 public key from PEM-encoded material.
      #
      # @deprecated Use {#new_rsa_v1_5_sha256_key} instead.
      # @param material [String] PEM-encoded RSA public key
      # @param key_id [String, nil] Optional key identifier
      # @return [RSA::Key] The loaded public key
      def new_rsa_v1_5_sha256_public_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::RSA::Key.new(key, id: key_id, digest: "SHA256")
      end

      # Generates a new HMAC-SHA256 symmetric key.
      #
      # HMAC keys are symmetric, meaning the same key is used for both
      # signing and verification. The key material must be kept secret.
      #
      # Uses the `hmac-sha256` algorithm identifier.
      #
      # @param key_id [String, nil] Optional key identifier
      # @return [HMAC::Key] A new 64-byte random HMAC key
      #
      # @example
      #   key = Linzer.generate_hmac_sha256_key("shared-secret")
      def generate_hmac_sha256_key(key_id = nil)
        material = OpenSSL::Random.random_bytes(64)
        Linzer::HMAC::Key.new(material, id: key_id, digest: "SHA256")
      end

      # Creates an HMAC-SHA256 key from existing key material.
      #
      # @param material [String] The secret key bytes (should be at least 32 bytes)
      # @param key_id [String, nil] Optional key identifier
      # @return [HMAC::Key] The HMAC key
      #
      # @example Loading from environment
      #   key = Linzer.new_hmac_sha256_key(
      #     Base64.decode64(ENV["HMAC_SECRET"]),
      #     "api-key"
      #   )
      def new_hmac_sha256_key(material, key_id = nil)
        Linzer::HMAC::Key.new(material, id: key_id, digest: "SHA256")
      end

      # Generates a new Ed25519 key pair.
      #
      # Ed25519 is a modern elliptic curve signature algorithm that provides
      # excellent security and performance. Recommended for new applications.
      #
      # Uses the `ed25519` algorithm identifier.
      #
      # @param key_id [String, nil] Optional key identifier
      # @return [Ed25519::Key] A new Ed25519 key pair
      #
      # @example
      #   key = Linzer.generate_ed25519_key("my-ed25519-key")
      def generate_ed25519_key(key_id = nil)
        material = OpenSSL::PKey.generate_key("ed25519")
        Linzer::Ed25519::Key.new(material, id: key_id)
      end

      # Loads an Ed25519 key from PEM-encoded material.
      #
      # Can load either a private key (for signing) or public key (for verification).
      #
      # @param material [String] PEM-encoded Ed25519 key
      # @param key_id [String, nil] Optional key identifier
      # @return [Ed25519::Key] The loaded key
      #
      # @example Loading a private key for signing
      #   key = Linzer.new_ed25519_key(File.read("ed25519.pem"), "my-key")
      def new_ed25519_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::Ed25519::Key.new(key, id: key_id)
      end

      # Loads an Ed25519 public key from PEM-encoded material.
      #
      # This is an alias for {#new_ed25519_key} for clarity when loading
      # public keys specifically.
      #
      # @param material [String] PEM-encoded Ed25519 public key
      # @param key_id [String, nil] Optional key identifier
      # @return [Ed25519::Key] The loaded public key
      #
      # @example
      #   pubkey = Linzer.new_ed25519_public_key(File.read("ed25519_pub.pem"), "my-key")
      def new_ed25519_public_key(material, key_id = nil)
        new_ed25519_key(material, key_id)
      end

      # Generates a new ECDSA P-256 key pair with SHA-256 digest.
      #
      # ECDSA P-256 (also known as secp256r1 or prime256v1) is widely supported
      # and provides good security for most applications.
      #
      # Uses the `ecdsa-p256-sha256` algorithm identifier.
      #
      # @param key_id [String, nil] Optional key identifier
      # @return [ECDSA::Key] A new ECDSA P-256 key pair
      #
      # @see https://www.rfc-editor.org/rfc/rfc4492.html#appendix-A RFC 4492 Appendix A
      #
      # @example
      #   key = Linzer.generate_ecdsa_p256_sha256_key("ecdsa-key")
      def generate_ecdsa_p256_sha256_key(key_id = nil)
        material = OpenSSL::PKey::EC.generate("prime256v1")
        Linzer::ECDSA::Key.new(material, id: key_id, digest: "SHA256")
      end

      # Loads an ECDSA P-256 key from PEM-encoded material.
      #
      # @param material [String] PEM-encoded EC key
      # @param key_id [String, nil] Optional key identifier
      # @return [ECDSA::Key] The loaded key
      def new_ecdsa_p256_sha256_key(material, key_id = nil)
        key = OpenSSL::PKey::EC.new(material)
        Linzer::ECDSA::Key.new(key, id: key_id, digest: "SHA256")
      end

      # Generates a new ECDSA P-384 key pair with SHA-384 digest.
      #
      # ECDSA P-384 (also known as secp384r1) provides higher security than P-256
      # at the cost of larger signatures and slightly slower operations.
      #
      # Uses the `ecdsa-p384-sha384` algorithm identifier.
      #
      # @param key_id [String, nil] Optional key identifier
      # @return [ECDSA::Key] A new ECDSA P-384 key pair
      #
      # @see https://www.rfc-editor.org/rfc/rfc4492.html#appendix-A RFC 4492 Appendix A
      #
      # @example
      #   key = Linzer.generate_ecdsa_p384_sha384_key("high-security-key")
      def generate_ecdsa_p384_sha384_key(key_id = nil)
        material = OpenSSL::PKey::EC.generate("secp384r1")
        Linzer::ECDSA::Key.new(material, id: key_id, digest: "SHA384")
      end

      # Loads an ECDSA P-384 key from PEM-encoded material.
      #
      # @param material [String] PEM-encoded EC key
      # @param key_id [String, nil] Optional key identifier
      # @return [ECDSA::Key] The loaded key
      def new_ecdsa_p384_sha384_key(material, key_id = nil)
        key = OpenSSL::PKey::EC.new(material)
        Linzer::ECDSA::Key.new(key, id: key_id, digest: "SHA384")
      end

      # Generates a new JWS key for the specified algorithm.
      #
      # This method generates keys compatible with JSON Web Signature (JWS)
      # format. Currently only EdDSA (Ed25519) is supported.
      #
      # @param algorithm [String] The JWS algorithm identifier (e.g., "EdDSA")
      # @return [JWS::Key] A new JWS-compatible key
      # @raise [Error] If the algorithm is not supported
      #
      # @example
      #   key = Linzer.generate_jws_key(algorithm: "EdDSA")
      def generate_jws_key(algorithm:)
        Linzer::JWS.generate_key(algorithm: algorithm)
      end

      # Imports a key from JWK (JSON Web Key) format.
      #
      # @param key [Hash] The JWK as a Hash (parsed from JSON)
      # @param params [Hash] Additional key parameters
      # @option params [String] :id Key identifier to use (overrides JWK "kid")
      # @return [JWS::Key] The imported key
      #
      # @example Importing from JWK
      #   jwk = JSON.parse(File.read("key.jwk"))
      #   key = Linzer.jwk_import(jwk)
      def jwk_import(key, params = {})
        Linzer::JWS.jwk_import(key, params)
      end
    end
  end
end
