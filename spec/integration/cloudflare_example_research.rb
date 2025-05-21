# frozen_string_literal: true

require "linzer/http/signature_feature"

#
# https://blog.cloudflare.com/web-bot-auth/
# https://http-message-signatures-example.research.cloudflare.com
# https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/
# https://github.com/thibmeu/http-message-signatures-directory
#
RSpec.describe "Tests against cloudflare example server", :integration do
  let(:debug) { false }

  let(:expected_msg) do
    /You successfully authenticated as owning the test public key/
  end

  let(:url) do
    "https://http-message-signatures-example.research.cloudflare.com"
  end

  let(:headers) do
    repo_url = "https://github.com/nomadium/linzer"
    {
      "signature-agent" => uri.authority,
      "user-agent"      => "Linzer/#{Linzer::VERSION} (+#{repo_url})"
    }
  end

  # test private key defined in Appendix B.1.4 of RFC 9421.
  let(:test_key_ed25519) do
    material = Linzer::RFC9421::Examples.test_key_ed25519
    Linzer.new_ed25519_key(material, "test-key-ed25519")
  end

  let(:other_key) { Linzer.generate_ed25519_key("other_key") }

  let(:net_http_client) do
    ->(uri) do
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http
    end
  end

  let(:bot_tag) { "web-bot-auth" }

  let(:linzer_http_get) do
    ->(uri, key) do
      now = Time.now.utc.to_i
      Linzer::HTTP.get(uri,
        key:    key,
        debug:  debug,
        params: {
          created: now,
          expires: now + 500,
          keyid:   key.key_id,
          tag:     bot_tag
        },
        covered_components: %w[@authority signature-agent],
        headers:            headers)
    end
  end

  let(:http_gem_client) do
    ->(key) do
      now = Time.now.utc.to_i

      http_signature_opts = {
        key: key,
        covered_components: %w[@authority signature-agent],
        params: {
          created: now,
          expires: now + 500,
          keyid:   key.key_id,
          tag:     bot_tag
        }
      }

      HTTP.use(http_signature: http_signature_opts)
    end
  end

  let(:sign!) do
    ->(key, request_or_response) do
      now = Time.now.utc.to_i
      Linzer.sign!(
        request_or_response,
        key: key,
        components: %w[@authority signature-agent],
        params: {
          created: now,
          expires: now + 500,
          keyid:   key.key_id,
          tag:     bot_tag
        }
      )
    end
  end

  context "main website" do
    let(:uri) { URI(url) }

    context "using Linzer::HTTP client" do
      it "authenticates successfully when using key defined in Appendix B.1.4" do
        response = linzer_http_get.call(uri, test_key_ed25519)

        expect(response.code).to eq("200")
        expect(response.body).to match expected_msg
      end

      it "does not authenticate request when an unknown key is used" do
        response = linzer_http_get.call(uri, other_key)

        expect(response.body).to_not match expected_msg
      end
    end

    context "with http gem client" do
      it "authenticates successfully when using key defined in Appendix B.1.4" do
        response =
          http_gem_client
            .call(test_key_ed25519)
            .headers(headers)
            .get(url)

        expect(response.code).to      eq(200)
        expect(response.body.to_s).to match expected_msg
      end

      it "does not authenticate request when an unknown key is used" do
        response =
          http_gem_client
            .call(other_key)
            .headers(headers)
            .get(url)

        expect(response.body.to_s).to_not match expected_msg
      end
    end
  end

  context "debug server" do
    let(:uri) { URI(url + "/debug") }

    context "using Net::HTTP client" do
      it "dumps incoming request headers" do
        request = Net::HTTP::Get.new(uri, headers)

        sign!.call(test_key_ed25519, request)
        response = net_http_client.call(uri).request(request)
        body     = response.body.to_s

        expect(response.code).to eq("200")

        puts body if debug

        expect(body).to include("signature: #{request["signature"]}")
        expect(body).to include("signature-input: #{request["signature-input"]}")
        expect(body).to include("host: #{uri.authority}")
      end
    end

    context "using http gem client client" do
      it "dumps incoming request headers" do
        request = HTTP::Request.new(verb: :get, uri: uri, headers: headers)

        sign!.call(test_key_ed25519, request)
        response = HTTP::Client.new.perform(request, HTTP::Options.new({}))
        body     = response.body.to_s

        expect(response.code).to eq(200)

        puts body if debug

        expect(body).to include("signature: #{request["signature"]}")
        expect(body).to include("signature-input: #{request["signature-input"]}")
        expect(body).to include("host: #{uri.authority}")
      end
    end
  end
end
