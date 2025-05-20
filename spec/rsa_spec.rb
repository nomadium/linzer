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
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      headers = request_data[:headers].merge({
        "host" => "origin.host.internal.example",
        "forwarded" => "for=192.0.2.123;host=example.com;proto=https"
      })
      request = Linzer::Test::RackHelper.new_request(:post, path, {}, headers)
      # Workaround the fact that `rack` reports a different `@authority`
      # than this example from RFC9421 expects
      allow(request).to receive(:authority).and_return("origin.host.internal.example")
      request
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
  end
end

RSpec.describe Linzer::Verifier do
  context "with RSA" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      headers = request_data[:headers].merge({
        "Forwarded" => "for=192.0.2.123;host=example.com;proto=https"
      })
      request = Linzer::Test::RackHelper.new_request(:post, path, {}, headers)
      # Workaround the fact that `rack` reports a different `@authority`
      # than this example from RFC9421 expects
      allow(request).to receive(:authority).and_return("origin.host.internal.example")
      request
    end

    let(:key_material) { Linzer::RFC9421::Examples.test_key_rsa_pub }

    let(:key_id) { "test-key-rsa" }

    it "fails to verify an invalid signature" do
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

    it "verifies a valid signature" do
      key = Linzer.new_rsa_v1_5_sha256_public_key(key_material, key_id)
      message = Linzer::Message.new(request)

      components = %w[@method @authority @path content-digest content-type content-length forwarded]
      timestamp  = 1618884480
      label      = "proxy_sig"

      signature = Linzer::Signature.build({
        "signature-input" => 'proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
        "signature" => "proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect(Linzer.verify(key, message, signature)).to eq(true)
    end
  end
end
