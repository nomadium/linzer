# frozen_string_literal: true

def signature(app, *args, &block)
  Rack::Lint.new Rack::Auth::Signature.new(app, *args, &block)
end

RSpec.describe Rack::Auth::Signature do
  let(:code) { 0 }

  let(:app) do
    lambda do |env|
      [200, {"content-type" => "text/plain"}, ["Hello, World!"]]
    end
  end

  # let(:signature) { described_class.new(app) }

  context "when used with default or no configuration" do
    it "responds with 401 to any request" do
      request = Rack::MockRequest.env_for
      response = signature(app).call(request)
      expect(response[code]).to eq(401)
    end
  end

  context "when configured to exclude a path" do
    it "skip any checks and allows the request" do
      request = Rack::MockRequest.env_for("/bar")
      response = signature(app, except: "/bar").call(request)
      expect(response[code]).to eq(200)
    end

    it "responds with 401 to requests to any other uri not excluded" do
      request = Rack::MockRequest.env_for
      response = signature(app, except: "/bar").call(request)
      expect(response[code]).to eq(401)
    end
  end

  context "when configured to exclude one or more paths" do
    it "responds with 401 to requests to any other uri not excluded" do
      request = Rack::MockRequest.env_for
      response = signature(app, except: %w[/foo /bar]).call(request)
      expect(response[code]).to eq(401)
    end
  end

  context "when requests with invalid or missing signature are received" do
    let(:settings) { {except: "/login"} }

    it "rejects requests with no signature headers" do
      request = Rack::MockRequest.env_for("/protected")
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with unparseable signature headers" do
      request = Rack::MockRequest.env_for("/protected")
      request["HTTP_SIGNATURE"]       = "..."
      request["HTTP_SIGNATURE_INPUT"] = "..."
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with incomplete signature headers" do
      request = Rack::MockRequest.env_for("/protected")
      request["HTTP_SIGNATURE"]       = "sig1=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig1=()"
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with signature headers with invalid parameters" do
      request = Rack::MockRequest.env_for("/protected")
      request["HTTP_SIGNATURE"]       = "sig2=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig2=();created=\"example\""
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with signature headers with incomplete parameters" do
      settings = {except: "/bar", signatures: {keyid_required: true}}
      request = Rack::MockRequest.env_for("/protected")
      created = Time.now.utc.to_i - 15
      request["HTTP_SIGNATURE"]       = "sig2=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig2=();created=#{created}"
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with signature headers with incomplete components" do
      request = Rack::MockRequest.env_for("/protected")
      created = Time.now.utc.to_i - 15
      request["HTTP_SIGNATURE"]       = "sig2=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig2=(\"@method\");created=#{created}"
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with signature headers with invalid signature" do
      request = Rack::MockRequest.env_for("/protected")
      components = '"date" "@authority" "@request-target" "@method" "x-foo"'
      created = Time.now.utc.to_i - 67
      params = "created=#{created};keyid=\"mykey\""
      request["HTTP_SIGNATURE"]       = "sig2=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig2=(#{components});#{params}"
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with signature headers with unknown keyid" do
      request = Rack::MockRequest.env_for("/protected")
      components = '"date" "@authority" "@request-target" "@method" "x-foo"'
      created = Time.now.utc.to_i - 67
      params = "created=#{created};keyid=\"unknown\""
      request["HTTP_SIGNATURE"]       = "sig2=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig2=(#{components});#{params}"
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with signature with no keyid and no default key set" do
      request = Rack::MockRequest.env_for("/protected")
      components = '"date" "@authority" "@request-target" "@method" "x-foo"'
      created = Time.now.utc.to_i - 67
      params = "created=#{created}"
      request["HTTP_SIGNATURE"]       = "sig2=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig2=(#{components});#{params}"
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    it "rejects requests with signature with unknown/unsupported algorithm" do
      keyid = "mykey"
      settings[:keys] = {keyid.to_sym => {material: "..."}}
      request = Rack::MockRequest.env_for("/protected")
      components = '"date" "@authority" "@request-target" "@method" "x-foo"'
      created = Time.now.utc.to_i - 67
      params = "created=#{created};keyid=\"#{keyid}\";alg=\"unsupported\""
      request["HTTP_SIGNATURE"]       = "sig2=\"foobar\""
      request["HTTP_SIGNATURE_INPUT"] = "sig2=(#{components});#{params}"
      response = signature(app, **settings).call(request)
      expect(response[code]).to eq(401)
    end

    context "requests with multiple signatures" do
      let(:signature_input) { 'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540' }
      let(:signatures) { "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:" }

      it "rejects requests with multiple signatures if none is selected" do
        keyid = "test-key-ecc-p256"
        settings[:keys] = {keyid.to_sym => {material: "..."}}
        request = Rack::MockRequest.env_for("/protected")
        request["HTTP_SIGNATURE_INPUT"] = signature_input
        request["HTTP_SIGNATURE"] = signatures
        response = signature(app, **settings).call(request)
        expect(response[code]).to eq(401)
      end

      context "when a label is selected" do
        it "processes the signature with the selected label" do
          keyid = "test-key-ecc-p256"
          settings[:keys] = {keyid.to_sym => {material: "..."}}
          settings[:signatures] = {default_label: "sig1"}
          request = Rack::MockRequest.env_for("/protected")
          request["HTTP_SIGNATURE_INPUT"] = signature_input
          request["HTTP_SIGNATURE"] = signatures
          response = signature(app, **settings).call(request)
          # as no valid key was passed, request is rejected
          expect(response[code]).to eq(401)
        end
      end
    end
  end

  context "when request with a valid signature is received" do
    let(:headers) {
      {
        "date"    => Time.now.utc.to_s,
        "x-field" => "value",
        "host"    => "example.org:80"
      }
    }
    let(:settings) { {except: "/login", keys: {}} }
    let(:keyid)    { "mykey" }
    let(:fields)   { %w[@method @request-target @authority date x-field]  }
    let(:request)  { Linzer.new_request(:post, "/protected", {}, headers) }
    let(:message)  { Linzer::Message.new(request) }

    it "allows the request to proceed [ed25519]" do
      key = Linzer.generate_ed25519_key(keyid)
      pubkey = key.material.public_to_pem
      settings[:keys][keyid.to_sym] = {alg: "ed25519", material: pubkey}

      signature = Linzer.sign(key, message, fields)
      env = Rack::MockRequest.env_for.merge(request.env)
      env.delete("rack.input")

      env["HTTP_SIGNATURE"]       = signature.to_h["signature"]
      env["HTTP_SIGNATURE_INPUT"] = signature.to_h["signature-input"]

      response = signature(app, **settings).call(env)
      expect(response[code]).to eq(200)
    end

    it "allows the request to proceed [hmac-sha256]" do
      key = Linzer.generate_hmac_sha256_key(keyid)
      settings[:keys][keyid.to_sym] = {alg: "hmac-sha256", material: key.material}

      signature = Linzer.sign(key, message, fields)
      env = Rack::MockRequest.env_for.merge(request.env)
      env.delete("rack.input")

      env["HTTP_SIGNATURE"]       = signature.to_h["signature"]
      env["HTTP_SIGNATURE_INPUT"] = signature.to_h["signature-input"]

      response = signature(app, **settings).call(env)
      expect(response[code]).to eq(200)
    end

    it "allows the request to proceed [rsa-pss-sha512]" do
      key = Linzer.generate_rsa_pss_sha512_key(2048, keyid)
      pubkey = key.material.public_to_pem
      settings[:keys][keyid.to_sym] = {alg: "rsa-pss-sha512", material: pubkey}

      signature = Linzer.sign(key, message, fields)
      env = Rack::MockRequest.env_for.merge(request.env)
      env.delete("rack.input")

      env["HTTP_SIGNATURE"]       = signature.to_h["signature"]
      env["HTTP_SIGNATURE_INPUT"] = signature.to_h["signature-input"]

      response = signature(app, **settings).call(env)
      expect(response[code]).to eq(200)
    end

    it "allows the request to proceed [ecdsa-p256-sha256]" do
      key = Linzer.generate_ecdsa_p256_sha256_key(keyid)
      pubkey = key.material.public_to_pem
      settings[:keys][keyid.to_sym] = {alg: "ecdsa-p256-sha256", material: pubkey}

      signature = Linzer.sign(key, message, fields)
      env = Rack::MockRequest.env_for.merge(request.env)
      env.delete("rack.input")

      env["HTTP_SIGNATURE"]       = signature.to_h["signature"]
      env["HTTP_SIGNATURE_INPUT"] = signature.to_h["signature-input"]

      response = signature(app, **settings).call(env)
      expect(response[code]).to eq(200)
    end

    it "allows the request to proceed [ecdsa-p384-sha384]" do
      key = Linzer.generate_ecdsa_p384_sha384_key(keyid)
      pubkey = key.material.public_to_pem
      settings[:keys][keyid.to_sym] = {alg: "ecdsa-p384-sha384", material: pubkey}

      signature = Linzer.sign(key, message, fields)
      env = Rack::MockRequest.env_for.merge(request.env)
      env.delete("rack.input")

      env["HTTP_SIGNATURE"]       = signature.to_h["signature"]
      env["HTTP_SIGNATURE_INPUT"] = signature.to_h["signature-input"]

      response = signature(app, **settings).call(env)
      expect(response[code]).to eq(200)
    end

    context "when signature checks are customized" do
      it "allows the request to proceed if checks succeed" do
        key = Linzer.generate_ecdsa_p384_sha384_key(keyid)
        pubkey = key.material.public_to_pem
        settings[:keys][keyid.to_sym] = {alg: "ecdsa-p384-sha384", material: pubkey}

        signature = Linzer.sign(key, message, fields, tag: "myapp")
        env = Rack::MockRequest.env_for.merge(request.env)
        env.delete("rack.input")

        env["HTTP_SIGNATURE"]       = signature.to_h["signature"]
        env["HTTP_SIGNATURE_INPUT"] = signature.to_h["signature-input"]

        middleware = signature(app, **settings) do
          def extra_checks?
            params["tag"] == "myapp" && params["alg"] != "rsa-pss-sha512]"
          end

          def acceptable?
            has_required_params? && has_required_components? && extra_checks?
          end
        end
        response = middleware.call(env)
        expect(response[code]).to eq(200)
      end

      it "rejects the request if checks do not pass" do
        key = Linzer.generate_hmac_sha256_key(keyid)
        settings[:keys][keyid.to_sym] = {alg: "hmac-sha256", material: key.material}

        signature = Linzer.sign(key, message, fields, tag: "myapp2")
        env = Rack::MockRequest.env_for.merge(request.env)
        env.delete("rack.input")

        env["HTTP_SIGNATURE"]       = signature.to_h["signature"]
        env["HTTP_SIGNATURE_INPUT"] = signature.to_h["signature-input"]

        middleware = signature(app, **settings) do
          def extra_checks?
            params["tag"] == "myapp2" && params.key?("nonce")
          end

          def acceptable?
            has_required_params? && has_required_components? && extra_checks?
          end
        end
        response = middleware.call(env)
        expect(response[code]).to eq(401)
      end
    end
  end
end
