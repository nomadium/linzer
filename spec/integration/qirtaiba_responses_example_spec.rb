# frozen_string_literal: true

require "linzer/faraday"

RSpec.describe "Signature verification on responses from a real server", :integration do
  let(:debug) { false }
  let(:url)   { "https://qirtaiba.org" }

  let(:test_key_ed25519) do
    Linzer.new_ed25519_key(Linzer::RFC9421::Examples.test_key_ed25519)
  end

  let(:server_pubkey) do
    pubkey_response = Faraday.get(url + "/pubkey")
    Linzer.new_ed25519_key(pubkey_response.body)
  end

  context "retrieving remote server public key" do
    let(:expected_pubkey) do
      <<~PEM
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEA/BQkmhWEzpQ1DwYhKAr2hBz8zpz1Q3z2CQ50VYY74YE=
        -----END PUBLIC KEY-----
      PEM
    end
    it "returns a known public key" do
      expect(server_pubkey.public?).to eq(true)
      expect(server_pubkey.material.public_to_pem).to eq(expected_pubkey)
    end

    it "verifies responses are signed by the expected key" do
      response = Faraday.get(url)
      expect(Linzer.verify!(response, key: server_pubkey)).to eq(true)
    end
  end

  context "unsigned requests" do
    it "/verify returns 401" do
      conn = Faraday.new(url: url)
      response = conn.get("/verify")

      expect(response.status).to eq(401)
      expect(response.env.request_headers.key?("signature")).to eq(false)
    end
  end

  context "signed requests" do
    it "/verify returns 200" do
      components = %w[@authority @method user-agent]
      conn = Faraday.new(url: url) do |f|
        f.request :http_signature, key: test_key_ed25519, components: components
        f.response :logger if debug
      end
      response = conn.get("/verify")

      expect(response.status).to eq(200)
      expect(response.env.request_headers.key?("signature")).to eq(true)
    end

    it "raises error when request cannot be signed" do
      components = %w[@authority @method user-agent missing-header]
      conn = Faraday.new(url: url) do |f|
        f.request :http_signature, key: test_key_ed25519, components: components
        f.response :logger if debug
      end

      expect { conn.get("/verify") }
        .to raise_error(Faraday::HttpSignature::SigningError)
    end

    it "does not raise error when request cannot be signed, when in non-strict mode" do
      components = %w[@authority @method user-agent missing-header]
      conn = Faraday.new(url: url) do |f|
        f.request :http_signature, key: test_key_ed25519, components: components, strict: false
        f.response :logger if debug
      end
      response = conn.get("/verify")

      # the request goes ahead without signature headers
      expect(response.status).to eq(401)
      expect(response.env.request_headers.key?("signature")).to eq(false)
    end
  end

  context "signed responses" do
    context "verification using expected key" do
      it "succeeds on response verification" do
        conn = Faraday.new(url: url) do |f|
          f.response :http_signature, verify_key: server_pubkey
          f.response :logger if debug
        end
        response = conn.get("/")

        expect(response.status).to eq(200)
        expect(response.env[:http_signature_verified]).to eq(true)
        expect(response.env[:http_signature]).to be_a(Linzer::Signature)
      end
    end

    context "verification errors" do
      let(:bad_key) { Linzer.generate_ed25519_key }

      it "raises error on response verification" do
        conn = Faraday.new(url: url) do |f|
          f.response :http_signature, verify_key: bad_key
          f.response :logger if debug
        end

        expect { conn.get("/") }
          .to raise_error(Faraday::HttpSignature::VerifyError, /Failed to verify/)
      end

      it "does not raise error on failed response verification, when in non-strict mode" do
        conn = Faraday.new(url: url) do |f|
          f.response :http_signature, verify_key: bad_key, strict: false
          f.response :logger if debug
        end
        response = conn.get("/")

        expect(response.status).to eq(200)
        expect(response.env[:http_signature_verified]).to eq(false)
      end
    end
  end

  context "signing requests and verifying requests" do
    it "can sign outgoing request and verify incoming response in one go" do
      components = %w[@authority @method user-agent]
      middleware_opts = {
        verify_response: true,
        verify_key:      server_pubkey,
        sign_key:        test_key_ed25519,
        components:      components,
        params:          {tag: "cool_tag", expires: Time.now.to_i + 500}
      }
      conn = Faraday.new(url: url) do |f|
        f.use :http_signature, middleware_opts
        f.response :logger if debug
      end
      response = conn.get("/verify")

      expect(response.status).to eq(200)
      expect(response.env.request_headers.key?("signature")).to       eq(true)
      expect(response.env.request_headers.key?("signature-input")).to eq(true)

      expect(response.env[:http_signature_verified]).to                   eq(true)
      expect(response.env[:http_signature].parameters.key?("created")).to eq(true)
    end
  end
end
