# frozen_string_literal: true

require "base64"

RSpec.describe Linzer do
  context "with HMAC using SHA256" do
    it "creates a HMAC SHA256 key" do
      key = Linzer.generate_hmac_sha256_key
      expect(key.material.to_str.bytesize).to     eq(64)
      expect(key.sign("data").to_str.bytesize).to eq(32)
    end
    it "does not leak HMAC SHA256 key underlying secret" do
      key = Linzer.generate_hmac_sha256_key
      expect(key.inspect).to_not match(/material/)
    end
    it "has a secret shared key" do
      key = Linzer.generate_hmac_sha256_key
      expect(key.private?).to eq(true)
      expect(key.public?).to  eq(false)
    end
  end
end

RSpec.describe Linzer::Signer do
  context "with HMAC using SHA-256" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
    end

    let(:test_shared_secret_key_material) do
      secret = Linzer::RFC9421::Examples.test_shared_secret
      Base64.strict_decode64(secret)
    end

    let(:key_id) { "test-shared-secret" }

    it "signs message with expected signature" do
      expected_input = 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"'
      expected_signature = "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"

      key = Linzer.new_hmac_sha256_key(test_shared_secret_key_material, key_id)

      message    = Linzer::Message.new(request)
      components = %w[date @authority content-type]
      timestamp  = 1618884473
      label      = "sig-b25"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature  = Linzer.sign(key, message, components, options)

      expect(expected_input).to     eq(signature.to_h["signature-input"])
      expect(expected_signature).to eq(signature.to_h["signature"])
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with HMAC using SHA-256" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
    end

    let(:test_shared_secret_key_material) do
      secret = Linzer::RFC9421::Examples.test_shared_secret
      Base64.strict_decode64(secret)
    end

    let(:key_id) { "test-shared-secret" }

    it "fails to verify an invalid signature" do
      key = Linzer.new_hmac_sha256_key(test_shared_secret_key_material, key_id)
      message = Linzer::Message.new(request)

      label      = "sig3"
      timestamp  = 1618884473
      components = %w[date @authority content-type]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig3=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
        "signature" => "sig3=:nreFRbPb+Mmhj7aXs1FmJmmwWXdoATGfffrgUx8cOTM=:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect { Linzer.verify(key, message, signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end

    it "verifies a valid signature" do
      key = Linzer.new_hmac_sha256_key(test_shared_secret_key_material, key_id)
      message = Linzer::Message.new(request)

      label      = "sig-b25"
      timestamp  = 1618884473
      components = %w[date @authority content-type]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
        "signature" => "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect(Linzer.verify(key, message, signature)).to eq(true)
    end
  end
end
