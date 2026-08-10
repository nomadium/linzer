# frozen_string_literal: true

require "linzer/jws"

RSpec.describe "Linzer.sign!" do
  context "with Web Bot Auth" do
    let(:uri)     { URI("https://example.com/api/resource") }
    let(:request) { Net::HTTP::Post.new(uri) }
    let(:key)     { Linzer::JWS.generate_key(algorithm: "EdDSA") }

    it "signs the request as specified by web bot auth spec" do
      signed_request = Linzer.sign!(request,
        key:          key,
        components:   %w[@method @path],
        label:        "my-sig",
        profile:      Linzer::Signature::Profile::WebBotAuth.new(
          agent:  "https://example.com/someagent"
        )
      )
      headers = signed_request.each_header.to_h
      signature = Linzer::Signature.build(headers)

      expect(signature.parameters).to          include("created")
      expect(signature.parameters).to          include("expires" => be > Time.now.utc.to_i)
      expect(signature.parameters["tag"]).to   eq("web-bot-auth")
      expect(signature.parameters["keyid"]).to eq(key.jwk_thumbprint)
      expect(signature.parameters).to          have_key("nonce")
      expect(signature.metadata).to            include('"@authority"').or include('"@target-uri"')
      expect(headers["signature-agent"]).to    eq("my-sig=\"https://example.com/someagent\"")
    end

    it "signs successfully with the default label when none is given" do
      # Regression test: WebBotAuth#agent needs a real signature label at
      # profile-apply time to key the Signature-Agent dictionary member.
      # sign! used to leave the label unset until Signer.sign's own
      # fallback, which runs too late as profile.apply(ctx) had already
      # seen a nil label by then, which serialized down to an empty
      # structured field key and raised Starry::SerializeError.
      signed_request = Linzer.sign!(request,
        key: key,
        components: %w[@method @path],
        profile: Linzer::Signature::Profile::WebBotAuth.new(
          agent: "https://example.com/someagent"
        )
      )
      headers = signed_request.each_header.to_h

      expect(headers["signature-agent"]).to eq('sig1="https://example.com/someagent"')
      expect(headers["signature-input"]).to start_with("sig1=")
    end
  end
end
