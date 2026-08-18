# frozen_string_literal: true

SimpleCov.command_name "test:integration"

#
# https://blog.cloudflare.com/web-bot-auth/
# https://http-message-signatures-example.research.cloudflare.com
# https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/
# https://github.com/thibmeu/http-message-signatures-directory
#
RSpec.describe "Signed requests against cloudflare example server", :integration do
  before(:all) do
    require "linzer/http/signature_feature"
    require "linzer/jws"
  end

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
      "signature-agent" => %("#{uri}"),
      "user-agent"      => "Linzer/#{Linzer::VERSION} (+#{repo_url})"
    }
  end

  # Test JWS key defined in Appendix B.1.4 of RFC 9421.
  let(:test_jws_key_ed25519) do
    jwk = Linzer::RFC9421::Examples.test_key_ed25519_jwk_format
    Linzer::JWS.jwk_import(JWT::JWK.import(jwk))
  end

  let(:other_key) { Linzer.generate_jws_key(algorithm: "EdDSA") }

  def net_http_client(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http
  end

  def linzer_http_get(uri, key)
    Linzer::HTTP.get(uri,
      key:    key,
      debug:  debug,
      covered_components: %w[@authority signature-agent],
      headers:            headers,
      profile:            :web_bot_auth)
  end

  def http_gem_client(key)
    http_signature_opts = {
      key: key,
      covered_components: %w[@authority signature-agent],
      profile:            :web_bot_auth
    }

    HTTP.use(http_signature: http_signature_opts)
  end

  def faraday_client(key)
    require "linzer/faraday"

    Faraday.new do |b|
      b.request :http_signature, key: key,
                                 components: %w[@authority signature-agent],
                                 profile: :web_bot_auth
    end
  end

  context "main website" do
    let(:uri) { URI(url) }

    context "using Linzer::HTTP client" do
      it "authenticates successfully when using key defined in Appendix B.1.4" do
        response = linzer_http_get(uri, test_jws_key_ed25519)

        expect(response.code).to eq("200")
        expect(response.body).to match expected_msg
      end

      it "does not authenticate request when an unknown key is used" do
        response = linzer_http_get(uri, other_key)

        expect(response.body).to_not match expected_msg
      end
    end

    context "with http gem client" do
      it "authenticates successfully when using key defined in Appendix B.1.4" do
        response =
          http_gem_client(test_jws_key_ed25519)
            .headers(headers)
            .get(url)

        expect(response.code).to      eq(200)
        expect(response.body.to_s).to match expected_msg
      end

      it "does not authenticate request when an unknown key is used" do
        response =
          http_gem_client(other_key)
            .headers(headers)
            .get(url)

        expect(response.body.to_s).to_not match expected_msg
      end
    end

    context "with faraday client" do
      it "authenticates successfully when using key defined in Appendix B.1.4" do
        response =
          faraday_client(test_jws_key_ed25519)
            .get(url,
                 nil,      # params
                 headers)

        expect(response.status).to    eq(200)
        expect(response.body.to_s).to match expected_msg
      end

      it "does not authenticate request when an unknown key is used" do
        response =
          faraday_client(other_key)
            .get(url,
                 nil,      # params
                 headers)

        expect(response.body.to_s).to_not match expected_msg
      end
    end
  end
end
