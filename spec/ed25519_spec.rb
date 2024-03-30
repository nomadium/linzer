# frozen_string_literal: true

RSpec.describe Linzer::Signer do
  context "with Ed25519" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer.new_request(:post, path, {}, request_data[:headers])
    end

    # B.1.4. Example Ed25519 Test Key
    #
    # -----BEGIN PUBLIC KEY-----
    # MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
    # -----END PUBLIC KEY-----
    #
    # -----BEGIN PRIVATE KEY-----
    # MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
    # -----END PRIVATE KEY-----
    #
    # ed25519 ruby library works with raw byte strings, so you have
    # to extract them from the PKCS #8 encoded file PEM format.
    #
    # XXX: should I write a helper method for that?
    #
    # $ openssl asn1parse -in private.pem -offset 14
    #     0:d=0  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:9F8362F87A484A954E6E740C5B4C0E84229139A20AA8AB56FF66586F6A7D29C5
    #
    # %w[9F8362F87A484A954E6E740C5B4C0E84229139A20AA8AB56FF66586F6A7D29C5].pack("H*")
    # => "\x9F\x83b\xF8zHJ\x95Nnt\f[L\x0E\x84\"\x919\xA2\n\xA8\xABV\xFFfXoj})\xC5"
    #
    let(:test_key_ed25519) do
      "\x9F\x83b\xF8zHJ\x95Nnt\f[L\x0E\x84\"\x919\xA2\n\xA8\xABV\xFFfXoj})\xC5"
    end

    let(:key_id) { "test-key-ed25519" }

    it "signs message with expected signature" do
      expected_input = 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
      expected_signature = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"

      key = Linzer.new_ed25519_key(test_key_ed25519, key_id)

      message    = Linzer::Message.new(request)
      components = %w[date @method @path @authority content-type content-length]
      timestamp  = 1618884473
      label      = "sig-b26"
      options    = {created: timestamp, keyid: key_id, label: label}

      signature  = Linzer.sign(key, message, components, options)

      expect(expected_input).to     eq(signature.to_h["signature-input"])
      expect(expected_signature).to eq(signature.to_h["signature"])
    end
  end
end

RSpec.describe Linzer::Verifier do
  context "with Ed25519" do
    let(:request) do
      request_data = Linzer::RFC9421::Examples.test_request_data
      path = request_data[:http]["path"]
      Linzer.new_request(:post, path, {}, request_data[:headers])
    end

    # $ openssl pkey -pubin -inform pem -in public.pem -noout -text
    # ED25519 Public-Key:
    # pub:
    #     26:b4:0b:8f:93:ff:f3:d8:97:11:2f:7e:bc:58:2b:
    #     23:2d:bd:72:51:7d:08:2f:e8:3c:fb:30:dd:ce:43:
    #     d1:bb
    #
    # %w[26B40B8F93FFF3D897112F7EBC582B232DBD72517D082FE83CFB30DDCE43D1BB].pack("H*")
    # => "&\xB4\v\x8F\x93\xFF\xF3\xD8\x97\x11/~\xBCX+#-\xBDrQ}\b/\xE8<\xFB0\xDD\xCEC\xD1\xBB"
    #
    # it can also be derived from private key object:
    # key.material.verify_key.to_bytes
    # => "&\xB4\v\x8F\x93\xFF\xF3\xD8\x97\x11/~\xBCX+#-\xBDrQ}\b/\xE8<\xFB0\xDD\xCEC\xD1\xBB"

    let(:test_key_ed25519_pub) do
      "&\xB4\v\x8F\x93\xFF\xF3\xD8\x97\x11/~\xBCX+#-\xBDrQ}\b/\xE8<\xFB0\xDD\xCEC\xD1\xBB"
    end

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
