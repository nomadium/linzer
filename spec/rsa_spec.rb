# frozen_string_literal: true

RSpec.describe Linzer do
  context "with RSA" do
    it "creates a RSA key" do
      key = Linzer.generate_rsa_v1_5_sha256_key(2048)
      expect(key.material.oid).to eq "rsaEncryption"
    end
  end
end

RSpec.describe Linzer::Signer do
  context "with RSA" do
    let(:request) do
      Linzer::Test::RequestHelper.example_proxy_request
    end

    let(:key_material) { Linzer::RFC9421::Examples.test_key_rsa }

    let(:key_id) { "test-key-rsa" }

    it "signs message with expected signature" do
      expected_input = 'proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540'
      expected_signature = "proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"

      key = Linzer.new_rsa_v1_5_sha256_key(key_material, key_id)

      message    = Linzer::Message.new(request)
      components = %w[@method @authority @path content-digest content-type content-length forwarded]
      timestamp  = 1618884480
      label      = "proxy_sig"
      options    = {created: timestamp, keyid: key_id, label: label, alg: "rsa-v1_5-sha256", expires: 1618884540}

      signature  = Linzer.sign(key, message, components, options)

      expect(signature.to_h["signature-input"]).to eq expected_input
      expect(signature.to_h["signature"]).to eq expected_signature
    end

    context "when a public key is given" do
      let(:pubkey) { Linzer::RFC9421::Examples.test_key_rsa_pub }

      it "fails to sign a message",
        skip: RUBY_VERSION < "3.1" && "Not supported on Ruby 3.0" do
        headers = {"Date" => "Time.now.to_s"}
        request = Linzer::Test::RackHelper.new_request(:post, "/test", {}, headers)
        key = Linzer.new_rsa_v1_5_sha256_key(pubkey)
        message    = Linzer::Message.new(request)
        components = %w[@method @path "date"]
        options    = {alg: "rsa-v1_5-sha256"}

        expect { Linzer.sign(key, message, components, options) }
          .to raise_error(Linzer::SigningError, /Private key is needed/)
      end
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with RSA" do
    let(:request) do
      Linzer::Test::RequestHelper.example_proxy_request
    end

    let(:key_material) { Linzer::RFC9421::Examples.test_key_rsa_pub }

    let(:key_id) { "test-key-rsa" }

    it "fails to verify an invalid signature",
      skip: RUBY_VERSION < "3.1" && "Not supported on Ruby 3.0" do
      key = Linzer.new_rsa_v1_5_sha256_public_key(key_material, key_id)
      message = Linzer::Message.new(request)

      label      = "sig3"
      timestamp  = 1618884473
      components = %w[date @authority content-type]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig3=("date" "@authority" "content-type");created=1618884473;keyid="test-key-rsa"',
        "signature" => "sig3=:nreFRbPb+Mmhj7aXs1FmJmmwWXdoATGfffrgUx8cOTM=:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect { Linzer.verify(key, message, signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end

    context "verifiable signatures" do
      let(:key) { Linzer.new_rsa_v1_5_sha256_public_key(key_material, key_id) }
      let(:message) { Linzer::Message.new(request) }
      let(:components) { %w[@method @authority @path content-digest content-type content-length forwarded] }
      let(:label) { "proxy_sig" }

      it "raises when expired signature is verified",
        skip: RUBY_VERSION < "3.1" && "Not supported on Ruby 3.0" do
        # This signature has expires=1618884540 (April 2021), which is already
        # in the past, so verification should reject it as expired.
        signature = Linzer::Signature.build({
          "signature-input" => 'proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
          "signature" => "proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"
        })

        expect { Linzer.verify(key, message, signature) }
          .to raise_error(Linzer::VerifyError, /[Ex]pire/)
      end

      it "verifies a valid signature",
        skip: RUBY_VERSION < "3.1" && "Not supported on Ruby 3.0" do
        # NOTE: created=1777049395 is ~April 2026. This signature has no
        # `expires` parameter so it won't be rejected on expiration grounds.
        timestamp = 1777049395
        signature = Linzer::Signature.build({
          "signature-input" => 'proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1777049395;keyid="test-key-rsa";alg="rsa-v1_5-sha256"',
          "signature" => "proxy_sig=:DPRgEu2IbVpD2Eq06PGVEMnuuPAaLq+1LQETWGhslI+jXGHnRKI11uyIDQHm0FIA2iQEOEmYJnhxoOaRL4N1EEl54Mi5TIt7IsX/YH0IwFwQNJpurV9SvB6RJ9Z7iQpvuCHSlfL6UiV0j8ovhKY0JxZeAccwVdvcZ20huc9nQylewmEihEfzVk29GJFHiCZrthillSM2RiZGJMVx8cS2Z32Da772XE87y8OU8J9lwQgRV8PQ9qNd6aKGcJrILMGYk2lqpA7SksD5nH/SjCQmm/MfLpPBuI19NKmAsDtNSAF2ZDKV1je4em9MZqk6BFDjHNH8LpHF1UCoU3ecYS3dMA==:"
        })

        expect(signature.label).to                 eq(label)
        expect(signature.components).to            eq(components)
        expect(signature.parameters["created"]).to eq(timestamp)
        expect(signature.parameters["keyid"]).to   eq(key_id)

        expect(Linzer.verify(key, message, signature)).to eq(true)
      end
    end
  end
end
