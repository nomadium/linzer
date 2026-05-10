# frozen_string_literal: true

RSpec.describe "Faraday::HttpSignature::Middleware" do
  before(:all) do
    require "linzer/faraday"
  end

  context "signing requests" do
    let(:conn) do
      Faraday.new do |b|
        b.request :http_signature, *options
        b.adapter :test do |stub|
          %w[get post].each do |method|
            stub.send(method, "/endpoint") do |env|
            end
          end
        end
      end
    end

    context "when no key is provided" do
      let(:options) { [] }

      it "raises error" do
        expect { conn.get("/endpoint") }
          .to raise_error(Faraday::HttpSignature::SigningError, /No signing key/)
      end
    end

    context "when a invalid key is provided" do
      let(:options) { [key: :not_a_linzer_key] }

      it "raises error" do
        expect { conn.get("/endpoint") }
          .to raise_error(Faraday::HttpSignature::SigningError, /Invalid key/)
      end
    end

    context "when a valid key is provided" do
      let(:options) { [key: Linzer.generate_ed25519_key] }

      it "attaches a HTTP signature to the submitted request" do
        response = conn.post("/endpoint")
        signature = Linzer::Signature.build(response.env.request_headers)

        expect(signature.to_h.key?("signature")).to eq(true)
      end
    end

    context "when a valid key is provided with signing_key option" do
      let(:options) { [sign_key: Linzer.generate_ed25519_key] }

      it "attaches a HTTP signature to the submitted request" do
        response = conn.post("/endpoint")
        signature = Linzer::Signature.build(response.env.request_headers)

        expect(signature.to_h.key?("signature")).to eq(true)
      end
    end

    context "when sign_request option is set to false" do
      let(:options) { [key: Linzer.generate_ed25519_key, sign_request: false] }

      it "does not attach a HTTP signature to the submitted request" do
        response = conn.post("/endpoint")

        expect(response.env.request_headers).to_not have_key("Signature")
      end
    end

    context "when the signature creation fails" do
      let(:options) do
        [key: Linzer.generate_ed25519_key, components: %w[not-found-header]]
      end

      it "raises error, request is not submitted" do
        expect { conn.get("/endpoint") }
          .to raise_error(Faraday::HttpSignature::SigningError,
                          /Missing component in message.*not-found-header.*/)
      end
    end

    context "when signature creation fails in non-strict mode" do
      let(:options) do
        [key: Linzer.generate_ed25519_key,
         components: %w[not-found-header],
         strict: false]
      end

      it "does not raise error" do
        expect { conn.get("/endpoint") }.to_not raise_error
      end

      it "submits the request without attaching HTTP signature" do
        response = conn.post("/endpoint")
        expect(response.env.request_headers).to_not have_key("Signature")
      end
    end
  end

  context "verifying responses" do
    let(:conn) do
      Faraday.new do |b|
        b.response :http_signature, *options
        b.adapter :test do |stub|
          %w[get post].each do |method|
            stub.send(method, "/endpoint") do |env|
            end
          end
        end
      end
    end

    context "when no key is provided" do
      let(:options) { [] }

      it "raises error" do
        expect { conn.get("/endpoint") }
          .to raise_error(Faraday::HttpSignature::VerifyError, /No verification key/)
      end
    end

    context "when a invalid key is provided" do
      let(:options) { [key: :not_a_linzer_key] }

      it "raises error" do
        expect { conn.get("/endpoint") }
          .to raise_error(Faraday::HttpSignature::VerifyError, /Invalid key/)
      end
    end

    context "when has valid signature" do
      let(:status)  { 200 }
      let(:created) { 1777238534 }
      let(:response_headers) do
        {
          "Date" => "Sun, 26 Apr 2026 21:20:16 GMT",
          "Signature" => "sig1=:kktN9SeZTkIpSeMDvzU4R80EbRUWCnkDU+FDTUpWCP0lEC4a6i0RJLZHyYY74Z+1DWO48NEMei9O9l8oYfrung==:",
          "Signature-Input" => "sig1=(\"@status\" \"date\");created=#{created}"
        }
      end
      let(:body) { nil }

      let(:conn) do
        Faraday.new do |b|
          b.response :http_signature, *options
          b.adapter :test do |stub|
            %w[get post].each do |method|
              stub.send(method, "/endpoint") do |env|
                [status, response_headers, body]
              end
            end
          end
        end
      end

      let(:verify_key) do
        key_material = Linzer::RFC9421::Examples.test_key_ecc_p256_pub
        Linzer.new_ecdsa_p256_sha256_key(key_material)
      end

      context "when a valid key is provided" do
        let(:options) { [key: verify_key] }

        it "has expected http_signature fields in response" do
          response = conn.post("/endpoint")

          expect(response.env[:http_signature_verified]).to be true
          expect(response.env[:http_signature]).to be_a(Linzer::Signature)

          signature = response.env[:http_signature]
          expect(signature.parameters["created"]).to eq(created)
        end
      end

      context "when a valid key is provided with verify_key option" do
        let(:options) { [verify_key: verify_key] }

        it "has expected http_signature fields in response" do
          response = conn.post("/endpoint")

          expect(response.env[:http_signature_verified]).to be true
          expect(response.env[:http_signature]).to be_a(Linzer::Signature)

          signature = response.env[:http_signature]
          expect(signature.parameters["created"]).to eq(created)
        end
      end
    end

    context "when verify_request option is set to false" do
      let(:options) { [key: Linzer.generate_ed25519_key, verify_response: false] }

      it "does not attempt to verify HTTP signature in response" do
        response = conn.post("/endpoint")

        expect(response.env[:http_signature_verified]).to be false
        expect(response.env).to_not have_key(:http_signature)
      end
    end

    context "when signature verification fails" do
      let(:options) { [key: Linzer.generate_ed25519_key] }

      it "raises error" do
        expect { conn.get("/endpoint") }
          .to raise_error(Faraday::HttpSignature::VerifyError,
                          /Cannot build signature/)
      end
    end

    context "when signature verification fails in non-strict mode" do
      let(:options) { [key: Linzer.generate_ed25519_key, strict: false] }

      it "does not raise error" do
        expect { conn.get("/endpoint") }.to_not raise_error
      end

      it "has not http_signature field in response" do
        response = conn.post("/endpoint")
        expect(response.env[:http_signature_verified]).to be false
        expect(response.env).to_not have_key(:http_signature)
      end

      it "has http_signature_verified field set to false in response" do
        response = conn.post("/endpoint")
        expect(response.env[:http_signature_verified]).to be false
        expect(response.env).to_not have_key(:http_signature)
      end
    end
  end

  context "signing requests and verifying responses" do
    context "requests and responses use the same middleware" do
      # XXX: investigate what's wrong with this unit test in truffleruby
      xit "has same options under request, response or use (combined)" do
        use_opts = Faraday::HttpSignature::Middleware.new(nil).options.sort
        request_opts = Faraday::HttpSignature::Middleware::Request.new(nil).options.sort
        response_opts = Faraday::HttpSignature::Middleware::Request.new(nil).options.sort

        expect(request_opts).to  eq(use_opts)
        expect(response_opts).to eq(request_opts)
      end
    end
  end
end
