# frozen_string_literal: true

require "linzer/jws"

RSpec.describe Linzer do
  context "with JWS algorithms" do
    it "creates a EdDSA key" do
      key = Linzer.generate_jws_key(algorithm: :EdDSA)
      expect(key.material.export[:crv]).to eq("Ed25519")
      expect(key).to be_a Linzer::JWS::Key
    end

    it "raises error when unsupported or unimplemented algorithm is requested" do
      expect { Linzer.generate_jws_key(algorithm: :foobar) }
        .to raise_error(Linzer::Error, /Algorithm 'foobar' is unsupported/)
    end
  end
end

RSpec.describe Linzer::JWS do
  describe "::jwk_import" do
    let(:test_key_ed25519_jwk_format) do
      Linzer::RFC9421::Examples.test_key_ed25519_jwk_format
    end

    it "imports a JWT::JWK key object and returns a JWS key" do
      key = Linzer::JWS.jwk_import(JWT::JWK.import(test_key_ed25519_jwk_format))
      expect(key).to be_a Linzer::JWS::Key
      expect(key.material.export[:crv]).to eq("Ed25519")
      expect(key.material.export[:kid]).to eq("test-key-ed25519")
    end

    it "imports a JWK hash and returns a JWS key" do
      key = Linzer::JWS.jwk_import(test_key_ed25519_jwk_format)
      expect(key).to be_a Linzer::JWS::Key
      expect(key.material.export[:crv]).to eq("Ed25519")
      expect(key.material.export[:kid]).to eq("test-key-ed25519")
    end
  end
end

RSpec.describe Linzer::Signer do
  context "with JWS EdDSA algorithm" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
    end

    let(:key_id) { "test-key-ed25519" }

    let(:test_key_ed25519_jwk_format) do
      Linzer::RFC9421::Examples.test_key_ed25519_jwk_format
    end

    it "signs message with expected signature" do
      expected_input = 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
      expected_signature = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"

      key = Linzer.jwk_import(test_key_ed25519_jwk_format)

      message    = Linzer::Message.new(request)
      components = %w[date @method @path @authority content-type content-length]
      timestamp  = 1618884473
      label      = "sig-b26"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature  = Linzer.sign(key, message, components, options)

      expect(signature.to_h["signature-input"]).to eq(expected_input)
      expect(signature.to_h["signature"]).to       eq(expected_signature)
    end
  end
end

RSpec.describe Linzer::Verifier do
  let(:request) do
    request_data = Linzer::RFC9421::Examples.test_request_data
    path = request_data[:http]["path"]
    Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
  end

  context "with JWS EdDSA algorithm" do
    let(:test_key_ed25519_pub_jwk_format) do
      Linzer::RFC9421::Examples
        .test_key_ed25519_jwk_format
        .except("d")
    end

    let(:key_id) { "test-key-ed25519" }

    it "fails to verify an invalid signature" do
      key = Linzer.generate_jws_key(algorithm: :EdDSA)
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
      key = Linzer.jwk_import(test_key_ed25519_pub_jwk_format)
      message = Linzer::Message.new(request)

      label      = "sig-b26"
      timestamp  = 1618884473
      components = %w[date @method @path @authority content-type content-length]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        "signature" => "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
      })

      expect(key.material.private?).to           eq(false)
      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect(Linzer.verify(key, message, signature)).to eq(true)
    end
  end

  context "with unsupported algorithm or not implemented yet" do
    it "fails to validate messages" do
      rsa_private_key = OpenSSL::PKey::RSA.new(2048)
      jws_key = Linzer.jwk_import(JWT::JWK.new(rsa_private_key))

      message = Linzer::Message.new(request)

      signature = Linzer::Signature.build({
        "signature-input" => 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        "signature" => "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
      })

      expect { Linzer.verify(jws_key, message, signature) }
        .to raise_error(Linzer::Error, /Unknown\/unsupported algorithm/)
    end
  end
end
