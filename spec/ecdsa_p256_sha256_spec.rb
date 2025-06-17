# frozen_string_literal: true

RSpec.describe Linzer do
  context "with ECDSA using Curve P-256 and SHA-256" do
    it "creates a HMAC SHA256 key" do
      key = Linzer.generate_ecdsa_p256_sha256_key
      expect(key.sign("data").to_str.bytesize).to eq(64)
    end
  end
end

RSpec.describe Linzer::Signer do
  context "with ECDSA using Curve P-256 and SHA-256" do
    let(:response) do
      response_data = Linzer::RFC9421::Examples.test_response_data
      body          = response_data[:body]
      status        = response_data[:http]["status"]
      headers       = response_data[:headers]
      Linzer::Test::RackHelper.new_response(body, status, headers)
    end

    let(:test_key_ecc_p256)     { Linzer::RFC9421::Examples.test_key_ecc_p256 }
    let(:test_key_ecc_p256_pub) { Linzer::RFC9421::Examples.test_key_ecc_p256_pub }

    let(:key_id) { "test-key-ecc-p256" }

    it "signs message with valid signature" do
      key = Linzer.new_ecdsa_p256_sha256_key(test_key_ecc_p256, key_id)

      message    = Linzer::Message.new(response)
      components = %w[@status content-type content-digest content-length]
      timestamp  = 1618884473
      label      = "sig-b26"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature  = Linzer.sign(key, message, components, options)

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)
      expect(signature.value.length).to          eq(64)

      pubkey = Linzer.new_ecdsa_p256_sha256_key(test_key_ecc_p256_pub, key_id)

      # a valid signature can be verified with public key
      expect(Linzer.verify(pubkey, message, signature)).to eq(true)
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with ECDSA using Curve P-256 and SHA-256" do
    let(:response) do
      response_data = Linzer::RFC9421::Examples.test_response_data
      body          = response_data[:body]
      status        = response_data[:http]["status"]
      headers       = response_data[:headers]
      Linzer::Test::RackHelper.new_response(body, status, headers)
    end

    let(:test_key_ecc_p256_pub) { Linzer::RFC9421::Examples.test_key_ecc_p256_pub }

    let(:key_id) { "test-key-ecc-p256" }

    it "fails to verify an invalid signature" do
      pubkey = Linzer.new_ecdsa_p256_sha256_key(test_key_ecc_p256_pub, key_id)
      message = Linzer::Message.new(response)

      label      = "sig1"
      timestamp  = 1618884473
      components = %w[@status content-type content-digest content-length]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig1=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
        "signature" => "sig1=:hbASojt/sjUgTzkSb6DtSPBDE3CYqFUOWqLA5Xo6tCrMg2E9IDFjpIoU1qrn8eui27W9AFwtw8hofnMpXba9Cg==:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)
      expect(signature.value.length).to          eq(64)

      expect { Linzer.verify(pubkey, message, signature) }
        .to raise_error(Linzer::Error, /Invalid signature/)
    end

    it "verifies a valid signature" do
      pubkey = Linzer.new_ecdsa_p256_sha256_key(test_key_ecc_p256_pub, key_id)
      message = Linzer::Message.new(response)

      label      = "sig-b24"
      timestamp  = 1618884473
      components = %w[@status content-type content-digest content-length]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
        "signature" => "sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)
      expect(signature.value.length).to          eq(64)

      expect(Linzer.verify(pubkey, message, signature)).to eq(true)
    end
  end
end
