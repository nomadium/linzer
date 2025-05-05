# frozen_string_literal: true

RSpec.describe Linzer::Signer do
  context "with ECDSA using Curve P-384 and SHA-384" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer::Test::Request.new_request(:post, path, {}, request_data[:headers])
    end

    let(:key_id)       { "test-key-ecc-p384" }

    let(:test_key_ecc_p384) do
      Linzer.generate_ecdsa_p384_sha384_key(key_id)
    end

    let(:test_key_ecc_p384_pub) do
      material = test_key_ecc_p384.material.public_to_pem
      Linzer.new_ecdsa_p384_sha384_key(material, key_id)
    end

    it "signs message with valid signature" do
      key = test_key_ecc_p384

      message    = Linzer::Message.new(request)
      components = %w[@method @authority content-type content-digest content-length]
      timestamp  = 1618884473
      label      = "sig384"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature  = Linzer.sign(key, message, components, options)

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)
      expect(signature.value.length).to          eq(96)

      pubkey = test_key_ecc_p384_pub

      # a valid signature can be verified with public key
      expect(Linzer.verify(pubkey, message, signature)).to eq(true)
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with ECDSA using Curve P-384 and SHA-384" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer::Test::Request.new_request(:post, path, {}, request_data[:headers])
    end

    let(:key_id)       { "test-key-ecc-p384" }

    let(:test_key_ecc_p384) do
      Linzer.generate_ecdsa_p384_sha384_key(key_id)
    end

    let(:test_key_ecc_p384_pub) do
      material = test_key_ecc_p384.material.public_to_pem
      Linzer.new_ecdsa_p384_sha384_key(material, key_id)
    end

    let(:example_valid_signature) do
      key = test_key_ecc_p384

      message    = Linzer::Message.new(request)
      components = %w[@method @authority content-type content-digest content-length]
      timestamp  = 1618884473
      label      = "sig384"
      options    = {created: timestamp, keyid: key_id, label: label}

      Linzer.sign(key, message, components, options)
    end

    it "fails to verify an invalid signature" do
      pubkey = test_key_ecc_p384_pub
      message = Linzer::Message.new(request)

      label      = "sig384"
      timestamp  = 1618884473
      components = %w[@method @authority content-type content-digest content-length]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig384=("@method" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p384"',
        "signature" => "sig384=:Ir9Zshr1b3LXwukCdHd+Eq0BSV0CeffPHEJQPvLjcvZIgff5AjSQIPTtQrSqBSq3woVv59Abc2jHEWDmcTMakexwbEgziEtvDHEJnvdKCoZun0ta8u2og2u8QjJB6cog:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)
      expect(signature.value.length).to          eq(96)

      expect { Linzer.verify(pubkey, message, signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end

    it "verifies a valid signature" do
      pubkey = test_key_ecc_p384_pub
      message = Linzer::Message.new(request)

      label      = "sig384"
      timestamp  = 1618884473
      components = %w[@method @authority content-type content-digest content-length]

      signature = example_valid_signature

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)
      expect(signature.value.length).to          eq(96)

      expect(Linzer.verify(pubkey, message, signature)).to eq(true)
    end
  end
end
