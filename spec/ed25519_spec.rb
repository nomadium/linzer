# frozen_string_literal: true

RSpec.describe Linzer::Signer do
  context "with Ed25519" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
    end

    let(:test_key_ed25519) do
      Linzer::RFC9421::Examples.test_key_ed25519
    end

    let(:key_id) { "test-key-ed25519" }

    let(:key) { Linzer.new_ed25519_key(test_key_ed25519, key_id) }

    it "signs message with expected signature" do
      expected_input = 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
      expected_signature = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"

      message    = Linzer::Message.new(request)
      components = %w[date @method @path @authority content-type content-length]
      timestamp  = 1618884473
      label      = "sig-b26"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature  = Linzer.sign(key, message, components, options)

      expect(expected_input).to     eq(signature.to_h["signature-input"])
      expect(expected_signature).to eq(signature.to_h["signature"])
    end

    it "derives public key from private key" do
      pubkey = key.material.public_to_pem
      expect(pubkey).to eq(Linzer::RFC9421::Examples.test_key_ed25519_pub)
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with Ed25519" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
    end

    let(:test_key_ed25519_pub) { Linzer::RFC9421::Examples.test_key_ed25519_pub }

    let(:key_id) { "test-key-ed25519" }

    it "fails to verify an invalid signature" do
      key = Linzer.generate_ed25519_key(key_id)
      message = Linzer::Message.new(request)

      label      = "sig1"
      timestamp  = 1618884473
      components = %w[date @authority content-type]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig1=("date" "@authority" "content-type");created=1618884473;keyid="test-key-ed25519"',
        "signature" => "sig1=:eNOPXCcriN1pOjp3ZOY3A6Cb1CtJMKgVhgsXAyfU6KtmUQZu+TPFAivS2KeaBEbBm9k1zhcJfDsJUcQhaYJyzA==:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect { Linzer.verify(key, message, signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end

    it "verifies a valid signature" do
      key = Linzer.new_ed25519_public_key(test_key_ed25519_pub, key_id)
      message = Linzer::Message.new(request)

      label      = "sig-b26"
      timestamp  = 1618884473
      components = %w[date @method @path @authority content-type content-length]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        "signature" => "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect(Linzer.verify(key, message, signature)).to eq(true)
    end
  end
end
