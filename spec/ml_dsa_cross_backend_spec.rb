# frozen_string_literal: true

require "linzer/ml_dsa"

RSpec.describe "ML-DSA cross-backend interoperability" do
  let(:data) { "cross-backend interoperability test data" }

  %w[44 65 87].each do |n|
    algorithm = "ml-dsa-#{n}"

    context "with #{algorithm}" do
      before do
        skip "OpenSSL doesn't support #{algorithm} on this build" unless
          Linzer::MLDSA.openssl_supported?(algorithm)
      end

      it "loads an OpenSSL-generated public key via the gem backend and verifies a signature from it" do
        openssl_key = Linzer.public_send("generate_ml_dsa_#{n}_key", backend: :openssl)
        raw_public = Linzer::MLDSA::OpenSSLKey.unwrap_raw_public_key(openssl_key.material)
        gem_public_key = Linzer.public_send("new_ml_dsa_#{n}_key", raw_public, backend: :ml_dsa)

        signature = openssl_key.sign(data)

        expect(gem_public_key.verify(signature, data)).to eq(true)
      end

      it "loads a gem-generated public key via the OpenSSL backend and verifies a signature from it" do
        gem_key = Linzer.public_send("generate_ml_dsa_#{n}_key", backend: :ml_dsa)
        raw_public = gem_key.material.public_key.to_bytes
        openssl_public_key = Linzer.public_send("new_ml_dsa_#{n}_key", raw_public, backend: :openssl)

        signature = gem_key.sign(data)

        expect(openssl_public_key.verify(signature, data)).to eq(true)
      end

      it "loads an OpenSSL-generated private key via the gem backend and signs with it" do
        openssl_key = Linzer.public_send("generate_ml_dsa_#{n}_key", backend: :openssl)
        raw_private = Linzer::MLDSA::OpenSSLKey.unwrap_raw_private_key(openssl_key.material)
        gem_key = Linzer.public_send("new_ml_dsa_#{n}_key", raw_private, backend: :ml_dsa)

        signature = gem_key.sign(data)

        expect(openssl_key.verify(signature, data)).to eq(true)
      end

      it "loads a gem-generated private key via the OpenSSL backend and signs with it" do
        gem_key = Linzer.public_send("generate_ml_dsa_#{n}_key", backend: :ml_dsa)
        raw_private = nil
        gem_key.material.with_bytes { |bytes| raw_private = bytes.dup }
        openssl_key = Linzer.public_send("new_ml_dsa_#{n}_key", raw_private, backend: :openssl)

        signature = openssl_key.sign(data)

        expect(gem_key.verify(signature, data)).to eq(true)
      end

      it "rejects a signature verified with an unrelated cross-backend key" do
        openssl_key = Linzer.public_send("generate_ml_dsa_#{n}_key", backend: :openssl)
        unrelated_gem_key = Linzer.public_send("generate_ml_dsa_#{n}_key", backend: :ml_dsa)

        signature = openssl_key.sign(data)

        expect(unrelated_gem_key.verify(signature, data)).to eq(false)
      end
    end
  end
end
