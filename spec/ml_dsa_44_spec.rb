# frozen_string_literal: true

# ML-DSA-44 requires OpenSSL 3.5+ with PQC signature algorithms enabled.
#
ML_DSA_44_SUPPORTED = begin
  OpenSSL::PKey.generate_key("ML-DSA-44")
  true
rescue OpenSSL::PKey::PKeyError
  false
end
ML_DSA_44_SKIP_REASON = "ML-DSA-44 requires OpenSSL 3.5+ with PQC signature algorithms enabled"

RSpec.describe Linzer::Signer do
  context "with ML-DSA-44" do
    let(:request) do
      req_data = Linzer::RFC9421::Examples.test_request_data
      path = req_data[:http]["path"]
      uri = URI("https://#{req_data[:headers]["host"]}#{path}")
      request = Net::HTTP::Post.new(uri)
      req_data[:headers].each { |h, v| request[h] = v }
      request
    end

    let(:test_key_ml_dsa_44)     { Linzer::RFC9421::Examples.test_key_ml_dsa_44 }
    let(:test_key_ml_dsa_44_pub) { Linzer::RFC9421::Examples.test_key_ml_dsa_44_pub }

    let(:key_id) { "test-key-ml-dsa-44" }

    let(:key) { Linzer.new_ml_dsa_44_key(test_key_ml_dsa_44, key_id) }

    it "signs a message with the expected signature-input and a verifiable signature",
      skip: !ML_DSA_44_SUPPORTED && ML_DSA_44_SKIP_REASON do
      expected_input = 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")' \
        ';created=1618884473;keyid="test-key-ml-dsa-44"'

      message    = Linzer::Message.new(request)
      components = %w[date @method @path @authority content-type content-length]
      timestamp  = 1618884473
      label      = "sig-b26"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature = Linzer.sign(key, message, components, options)

      expect(signature.to_h["signature-input"]).to eq(expected_input)
      # ML-DSA-44 signing is randomized, so (unlike Ed25519) we cannot assert
      # a fixed signature value. Assert its shape and fixed FIPS 204 size,
      # and that it actually verifies, instead.
      expect(signature.to_h["signature"]).to match(/\Asig-b26=:.+:\z/)
      expect(signature.value.bytesize).to eq(2420)

      pubkey = Linzer.new_ml_dsa_44_public_key(test_key_ml_dsa_44_pub, key_id)
      expect(Linzer.verify(pubkey, message, signature)).to eq(true)
    end

    it "derives public key from private key",
      skip: !ML_DSA_44_SUPPORTED && ML_DSA_44_SKIP_REASON do
      expect(key.material.public_to_pem).to eq(test_key_ml_dsa_44_pub)
    end
  end

  context "with raw FIPS 204 key encoding" do
    it "round-trips a freshly generated key pair through the raw public/private key helpers",
      skip: !ML_DSA_44_SUPPORTED && ML_DSA_44_SKIP_REASON do
      original = Linzer.generate_ml_dsa_44_key

      priv_key = Linzer.new_ml_dsa_44_raw_private_key(original.material.raw_private_key)
      pub_key  = Linzer.new_ml_dsa_44_raw_public_key(original.material.raw_public_key)

      signature = priv_key.sign("hello, post-quantum world")

      expect(signature.bytesize).to eq(2420)
      expect(pub_key.verify(signature, "hello, post-quantum world")).to eq(true)
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with ML-DSA-44" do
    # Official test vector from the C2SP httpsig-pq specification
    # (Post-Quantum Algorithms for HTTP Message Signatures), v0.2.0:
    # https://github.com/C2SP/C2SP/blob/httpsig-pq/v0.2.0/httpsig-pq.md
    let(:vector) { Linzer::RFC9421::Examples.test_ml_dsa_44_vector }

    let(:request) do
      req = vector[:request]
      uri = URI("https://#{req[:host]}#{req[:path]}?#{req[:query]}")
      request = Net::HTTP::Get.new(uri)
      request["date"] = req[:date]
      request
    end

    let(:message) { Linzer::Message.new(request) }

    let(:pubkey) do
      raw_pubkey = Base64.decode64(vector[:public_key_b64])
      Linzer.new_ml_dsa_44_raw_public_key(raw_pubkey, vector[:keyid])
    end

    let(:signature) do
      Linzer::Signature.build({
        "signature-input" => vector[:signature_input],
        "signature"       => "#{vector[:label]}=:#{vector[:signature_b64]}:"
      })
    end

    it "verifies the official C2SP httpsig-pq ML-DSA-44 test vector",
      skip: !ML_DSA_44_SUPPORTED && ML_DSA_44_SKIP_REASON do
      expect(signature.label).to                 eq(vector[:label])
      expect(signature.components).to            eq(vector[:components])
      expect(signature.parameters["created"]).to eq(vector[:created])
      expect(signature.parameters["keyid"]).to   eq(vector[:keyid])
      expect(signature.parameters["alg"]).to     eq("ml-dsa-44")

      expect(Linzer.verify(pubkey, message, signature)).to eq(true)
    end

    # The next two examples mirror negative test cases from the C2SP spec's
    # "Test vectors > Negative test cases" table: a flipped signature bit,
    # and a modified covered component, must both be rejected.

    it "rejects a bit-flipped signature over the same message",
      skip: !ML_DSA_44_SUPPORTED && ML_DSA_44_SKIP_REASON do
      tampered = Base64.decode64(vector[:signature_b64])
      tampered.setbyte(0, tampered.getbyte(0) ^ 1)

      tampered_signature = Linzer::Signature.build({
        "signature-input" => vector[:signature_input],
        "signature"       => "#{vector[:label]}=:#{Base64.strict_encode64(tampered)}:"
      })

      expect { Linzer.verify(pubkey, message, tampered_signature) }
        .to raise_error(Linzer::VerifyError, /Invalid signature/)
    end

    it "rejects the signature once the covered date component is modified",
      skip: !ML_DSA_44_SUPPORTED && ML_DSA_44_SKIP_REASON do
      tampered_request = request.clone
      tampered_request["date"] = "Mon, 06 Jul 2026 20:00:01 GMT"
      tampered_message = Linzer::Message.new(tampered_request)

      expect { Linzer.verify(pubkey, tampered_message, signature) }
        .to raise_error(Linzer::VerifyError, /Invalid signature/)
    end
  end
end
