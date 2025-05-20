# frozen_string_literal: true

RSpec.describe Linzer do
  context "with RSASSA-PSS" do
    it "creates a RSASSA-PSS key" do
      key = Linzer.generate_rsa_pss_sha512_key(2048)
      expect(key.material.oid).to eq "RSASSA-PSS"
    end
  end
end

RSpec.describe Linzer::Signer do
  context "with RSASSA-PSS" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      request = Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
      request.env["QUERY_STRING"] = "param=Value&Pet=dog"
      request
    end

    let(:key_material) { Linzer::RFC9421::Examples.test_key_rsa_pss }

    let(:key_id) { "test-key-rsa-pss" }

    it "signs message with expected signature" do
      expected_input = 'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"'

      key = Linzer.new_rsa_pss_sha512_key(key_material, key_id)

      message    = Linzer::Message.new(request)
      components = %w[date @method @path @query @authority content-type content-digest content-length]
      timestamp  = 1618884473
      label      = "sig-b23"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature  = Linzer.sign(key, message, components, options)

      expect(signature.to_h["signature-input"]).to eq expected_input
      # RSASSA-PSS is non-deterministic, so cannot make an exact comparison
      expect(signature.to_h["signature"]).to match(/^sig-b23=:.+:$/)
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with RSASSA-PSS" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      request = Linzer::Test::RackHelper.new_request(:post, path, {}, request_data[:headers])
      request.env["QUERY_STRING"] = "param=Value&Pet=dog"
      request
    end

    let(:key_material) { Linzer::RFC9421::Examples.test_key_rsa_pss_pub }

    let(:key_id) { "test-key-rsa-pss" }

    it "fails to verify an invalid signature" do
      key = Linzer.new_rsa_pss_sha512_public_key(key_material, key_id)
      message = Linzer::Message.new(request)

      label      = "sig3"
      timestamp  = 1618884473
      components = %w[date @authority content-type]

      signature = Linzer::Signature.build({
        "signature-input" => 'sig3=("date" "@authority" "content-type");created=1618884473;keyid="test-key-rsa-pss"',
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
      key = Linzer.new_rsa_pss_sha512_public_key(key_material, key_id)
      message = Linzer::Message.new(request)

      components = %w[date @method @path @query @authority content-type content-digest content-length]
      timestamp  = 1618884473
      label      = "sig-b23"

      signature = Linzer::Signature.build({
        "signature-input" => 'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
        "signature" => "sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:"
      })

      expect(signature.label).to                 eq(label)
      expect(signature.components).to            eq(components)
      expect(signature.parameters["created"]).to eq(timestamp)
      expect(signature.parameters["keyid"]).to   eq(key_id)

      expect(Linzer.verify(key, message, signature)).to eq(true)
    end
  end
end
