# frozen_string_literal: true

module Linzer
  class Key
    module Helper
      def generate_rsa_pss_sha512_key(size, key_id = nil)
        material = OpenSSL::PKey.generate_key("RSASSA-PSS")
        Linzer::RSAPSS::Key.new(material, id: key_id, digest: "SHA512")
      end

      def new_rsa_pss_sha512_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::RSAPSS::Key.new(key, id: key_id, digest: "SHA512")
      end

      # XXX: investigate: was this method made redundant after:
      # https://github.com/nomadium/linzer/pull/10
      def new_rsa_pss_sha512_public_key(material, key_id = nil)
        key = OpenSSL::PKey::RSA.new(material)
        Linzer::RSAPSS::Key.new(key, id: key_id, digest: "SHA512")
      end

      def generate_rsa_v1_5_sha256_key(size, key_id = nil)
        material = OpenSSL::PKey::RSA.generate(size)
        Linzer::RSA::Key.new(material, id: key_id, digest: "SHA256")
      end

      def new_rsa_v1_5_sha256_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::RSA::Key.new(key, id: key_id, digest: "SHA256")
      end

      # XXX: investigate: was this method made redundant after:
      # https://github.com/nomadium/linzer/pull/10
      def new_rsa_v1_5_sha256_public_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::RSA::Key.new(key, id: key_id, digest: "SHA256")
      end

      def generate_hmac_sha256_key(key_id = nil)
        material = OpenSSL::Random.random_bytes(64)
        Linzer::HMAC::Key.new(material, id: key_id, digest: "SHA256")
      end

      def new_hmac_sha256_key(material, key_id = nil)
        Linzer::HMAC::Key.new(material, id: key_id, digest: "SHA256")
      end

      def generate_ed25519_key(key_id = nil)
        material = OpenSSL::PKey.generate_key("ed25519")
        Linzer::Ed25519::Key.new(material, id: key_id)
      end

      def new_ed25519_key(material, key_id = nil)
        key = OpenSSL::PKey.read(material)
        Linzer::Ed25519::Key.new(key, id: key_id)
      end

      def new_ed25519_public_key(material, key_id = nil)
        new_ed25519_key(material, key_id)
      end

      # https://www.rfc-editor.org/rfc/rfc4492.html#appendix-A
      # Table 6: Equivalent curves defined by SECG, ANSI, and NIST
      # secp256r1   |  prime256v1   |   NIST P-256
      def generate_ecdsa_p256_sha256_key(key_id = nil)
        material = OpenSSL::PKey::EC.generate("prime256v1")
        Linzer::ECDSA::Key.new(material, id: key_id, digest: "SHA256")
      end

      def new_ecdsa_p256_sha256_key(material, key_id = nil)
        key = OpenSSL::PKey::EC.new(material)
        Linzer::ECDSA::Key.new(key, id: key_id, digest: "SHA256")
      end

      # https://www.rfc-editor.org/rfc/rfc4492.html#appendix-A
      # Table 6: Equivalent curves defined by SECG, ANSI, and NIST
      # secp384r1   |               |   NIST P-384
      def generate_ecdsa_p384_sha384_key(key_id = nil)
        material = OpenSSL::PKey::EC.generate("secp384r1")
        Linzer::ECDSA::Key.new(material, id: key_id, digest: "SHA384")
      end

      def new_ecdsa_p384_sha384_key(material, key_id = nil)
        key = OpenSSL::PKey::EC.new(material)
        Linzer::ECDSA::Key.new(key, id: key_id, digest: "SHA384")
      end

      def generate_jws_key(algorithm:)
        Linzer::JWS.generate_key(algorithm: algorithm)
      end

      def jwk_import(key, params = {})
        Linzer::JWS.jwk_import(key, params)
      end
    end
  end
end
