# frozen_string_literal: true

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

  # test private key defined in Appendix B.1.4 of RFC 9421.
  let(:key) do
    material = Linzer::RFC9421::Examples.test_key_ed25519
    Linzer.new_ed25519_key(material, "test-key-ed25519")
  end

  let(:http_client) do
    ->(uri) do
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http
    end
  end

  let(:bot_tag) { "web-bot-auth" }

  let(:http_get) do
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
        headers:            {"signature-agent" => uri.authority})
    end
  end

  context "main website" do
    let(:uri) { URI(url) }

    it "authenticates successfully when using key defined in Appendix B.1.4" do
      response = http_get.call(uri, key)

      expect(response.code).to eq("200")
      expect(response.body).to match expected_msg
    end

    it "does not authenticate request when an unknown key is used" do
      other_key = Linzer.generate_ed25519_key("other_key")
      response  = http_get.call(uri, other_key)

      expect(response.body).to_not match expected_msg
    end
  end

  context "debug server" do
    it "dumps incoming request headers" do
      uri     = URI(url + "/debug")
      request = Net::HTTP::Get.new(uri)

      now = Time.now.utc.to_i
      request["signature-agent"] = uri.authority

      Linzer.sign!(
        request,
        key: key,
        components: %w[@authority signature-agent],
        params: {
          created: now,
          expires: now + 500,
          keyid:   key.key_id,
          tag:     bot_tag
        }
      )

      response = http_client.call(uri).request(request)

      expect(response.code).to eq("200")

      puts response.body if debug

      expect(response.body)
        .to include("signature: #{request["signature"]}")
      expect(response.body)
        .to include("signature-input: #{request["signature-input"]}")
      expect(response.body)
        .to include("host: #{uri.authority}")
    end
  end
end
