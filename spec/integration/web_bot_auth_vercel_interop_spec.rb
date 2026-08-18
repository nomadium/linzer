# frozen_string_literal: true

require_relative "support/test_http_clients"

require "linzer/jws"
require "json"

#
# https://github.com/fingerprintjs/wba-verify-api, a third-party,
# Web Bot Auth verifier, independent of Cloudflare's own research
# server (see cloudflare_example_research_spec.rb). This points
# Signature-Agent at linzer.lol's real, live keys directory, so it
# confirms an entirely independent implementation can fetch that
# directory, resolve the keyid via RFC 7638 thumbprint, and verify the
# signature end-to-end.
#
# test_jws_key_ed25519 (RFC 9421 Appendix B.1.4's test key) is the exact
# same Ed25519 keypair linzer.lol publishes in its own directory, the
# same test vector reused by the RFC, the Web Bot Auth draft's own
# examples, and this deployment, which is why signing with it verifies
# successfully here.
#
RSpec.describe "Signed requests verified by wba-verify-api", :integration do
  include Linzer::Test::HTTPClients

  let(:debug)   { false }
  let(:url)     { "https://wba-quickstart.vercel.app/api/verify" }
  let(:uri)     { URI(url) }
  let(:headers) { {"signature-agent" => %("https://linzer.lol/")} }

  # Test JWS key defined in Appendix B.1.4 of RFC 9421.
  let(:test_jws_key_ed25519) do
    jwk = Linzer::RFC9421::Examples.test_key_ed25519_jwk_format
    Linzer::JWS.jwk_import(JWT::JWK.import(jwk))
  end

  let(:unknown_key) { Linzer.generate_jws_key(algorithm: "EdDSA") }

  let(:another_known_key) do
    Linzer.jwk_import({
      kty: "OKP", crv: "Ed25519",
      x: "Juh8z8YWx41i5Wge0RkTr1QOhUgql94YUF8d-RX8r3Q",
      d: "LoZn3X1_5eWYl9DP2k7f0OT2NeEhRcmHEVQIoFwvjyY",
      kid: "GaqHcVWPJzoDr-Nop5Y6Jig7yY6QYq40cMiqh_24XyA"
    })
  end

  def error_code(response)
    JSON.parse(response.body.to_s)["errors"].first["code"]
  end

  it "verifies a request signed against linzer.lol's published key" do
    response = linzer_http_get(uri, test_jws_key_ed25519, {alg: "ed25519"})
    body     = JSON.parse(response.body.to_s)

    expect(response.code).to            eq("200")
    expect(body["status"]).to           eq("success")
    expect(body["details"]["keyId"]).to eq(test_jws_key_ed25519.jwk_thumbprint)
  end

  it "verifies a request signed with another known key" do
    response = linzer_http_get(uri, another_known_key, {alg: "ed25519"})
    body     = JSON.parse(response.body.to_s)

    expect(response.code).to            eq("200")
    expect(body["status"]).to           eq("success")
    expect(body["details"]["keyId"]).to eq(another_known_key.jwk_thumbprint)
  end

  it "rejects a request signed with a key absent from the directory" do
    response = linzer_http_get(uri, unknown_key, {alg: "ed25519"})

    expect(response.code).to        eq("400")
    expect(error_code(response)).to eq("KEY_NOT_FOUND")
  end

  # wba-verify-api requires `alg` as an explicit @signature-params member
  # and pins it to exactly "ed25519".
  # Linzer's WebBotAuth profile itself never sets a default
  # for it, unlike expires/tag/keyid, so callers must supply it (as the
  # test above does).
  context "with an invalid alg parameter" do
    it "rejects a request that omits alg entirely" do
      response = linzer_http_get(uri, test_jws_key_ed25519, {})

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
    end

    it "rejects a request with an alg value other than ed25519" do
      response = linzer_http_get(uri, test_jws_key_ed25519, {alg: "eddsa"})

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
    end
  end

  # RFC 9421 Section 3.3 timestamp checks, enforced directly on the
  # signature's own created/expires params.
  context "with an invalid signature timestamp" do
    it "rejects a signature that has already expired" do
      response = linzer_http_get(uri, test_jws_key_ed25519,
        {alg: "ed25519", expires: Time.now.to_i - 10})

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("SIGNATURE_EXPIRED")
    end

    it "rejects a signature created more than an hour ago" do
      response = linzer_http_get(uri, test_jws_key_ed25519,
        {alg: "ed25519", created: Time.now.to_i - 4000})

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("SIGNATURE_TOO_OLD")
    end

    it "rejects a signature created more than 5 minutes in the future" do
      response = linzer_http_get(uri, test_jws_key_ed25519,
        {alg: "ed25519", created: Time.now.to_i + 600})

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("SIGNATURE_TIMESTAMP_FUTURE")
    end
  end

  context "with an invalid signature-agent" do
    context "pointing at a host with no published directory" do
      let(:headers) { {"signature-agent" => %("https://example.com/")} }

      it "rejects the request" do
        response = linzer_http_get(uri, test_jws_key_ed25519, {alg: "ed25519"})

        expect(response.code).to        eq("400")
        expect(error_code(response)).to eq("KEY_DIRECTORY_FETCH_FAILED")
      end
    end

    context "with a path component" do
      let(:headers) { {"signature-agent" => %("https://linzer.lol/foo")} }

      it "rejects the request" do
        response = linzer_http_get(uri, test_jws_key_ed25519, {alg: "ed25519"})

        expect(response.code).to        eq("400")
        expect(error_code(response)).to eq("INVALID_SIGNATURE_AGENT")
      end
    end

    context "using http instead of https" do
      let(:headers) { {"signature-agent" => %("http://linzer.lol/")} }

      it "rejects the request" do
        response = linzer_http_get(uri, test_jws_key_ed25519, {alg: "ed25519"})

        expect(response.code).to        eq("400")
        expect(error_code(response)).to eq("INVALID_SIGNATURE_AGENT")
      end
    end

    # 443 wouldn't trigger this: URL parsers normalize away a port that
    # already matches the scheme's default.
    context "with an explicit non-default port" do
      let(:headers) { {"signature-agent" => %("https://linzer.lol:8443/")} }

      it "rejects the request" do
        response = linzer_http_get(uri, test_jws_key_ed25519, {alg: "ed25519"})

        expect(response.code).to        eq("400")
        expect(error_code(response)).to eq("INVALID_SIGNATURE_AGENT")
      end
    end
  end

  it "rejects a request sent with no signature headers at all" do
    response = net_http_client(uri).request(Net::HTTP::Get.new(uri, {}))

    expect(response.code).to        eq("400")
    expect(error_code(response)).to eq("MISSING_SIGNATURE_HEADERS")
  end

  it "rejects a signed request missing the Signature-Agent header" do
    # No signature-agent in `headers`, and it's dropped from `components`
    # too. Linzer can't cover a header that was never set on the message.
    response = sign_and_get(test_jws_key_ed25519, headers: {},
      components: %w[@authority])

    expect(response.code).to        eq("400")
    expect(error_code(response)).to eq("MISSING_SIGNATURE_AGENT")
  end

  it "rejects a request whose tag is not web-bot-auth" do
    response = sign_and_get(test_jws_key_ed25519,
      params: {alg: "ed25519", tag: "not-web-bot-auth"})

    expect(response.code).to        eq("400")
    expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
  end

  # Test endpoint requires both REQUIRED_COVERED_COMPONENTS
  # ("@authority" and "signature-agent"), same INVALID_SIGNATURE_INPUT
  # code either way, just naming whichever one is actually missing.
  context "with a required covered component missing" do
    it "rejects a request that doesn't cover signature-agent" do
      # signature-agent is still a real header on the request (via
      # `headers`, the default from sign_and_get), just left out of
      # what's covered.
      response = sign_and_get(test_jws_key_ed25519, components: %w[@authority])

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
    end

    it "rejects a request that doesn't cover @authority" do
      # WebBotAuth's default profile (params: :recommended) actively
      # defends against this: set_params! re-adds @authority or
      # @target-uri whenever both are missing from components, and also
      # fills in expires/tag/keyid. Disabling that (params: nil) is the
      # only way to get a request that's otherwise well-formed but
      # genuinely missing @authority, which means expires/tag/keyid
      # have to be supplied by hand instead of relying on the profile.
      profile =
        Linzer::Signature::Profile::WebBotAuth.new(params: nil, nonce: :generate)

      response = sign_and_get(test_jws_key_ed25519,
        components: %w[signature-agent],
        profile:    profile,
        params: {
          alg:     "ed25519",
          tag:     "web-bot-auth",
          keyid:   test_jws_key_ed25519.jwk_thumbprint,
          expires: Time.now.to_i + 3600
        })

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
    end
  end

  it "rejects a request with an empty nonce" do
    # WebBotAuth's default profile (nonce: :generate) unconditionally
    # overwrites ctx.params[:nonce], clobbering any nonce: "" passed in
    # params, so disabling generation is the only way to make an empty
    # nonce actually reach the wire.
    no_nonce_profile = Linzer::Signature::Profile::WebBotAuth.new(nonce: nil)
    response = sign_and_get(test_jws_key_ed25519,
      profile: no_nonce_profile, params: {alg: "ed25519", nonce: ""})

    expect(response.code).to        eq("400")
    expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
  end

  # Linzer only ever emits well-formed Signature-Input syntax, so these
  # can't be reached through its own signing API; same trick as the
  # tampered-signature test below: sign normally, then hand-corrupt the
  # header string before sending. Unlike the rest of this file, these test
  # wba-verify-api's own parser hardening, rather than Linzer/wba-verify-api
  # interop, since Linzer would never produce input like this against any verifier.
  context "with malformed Signature-Input syntax" do
    it "rejects a covered component that isn't double-quoted" do
      response = sign_and_get(test_jws_key_ed25519) do |request|
        request["signature-input"] =
          request["signature-input"].sub('"@authority"', "@authority")
      end

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
    end

    it "rejects a keyid parameter that isn't double-quoted" do
      kid = test_jws_key_ed25519.jwk_thumbprint

      response = sign_and_get(test_jws_key_ed25519) do |request|
        request["signature-input"] =
          request["signature-input"].sub(%(keyid="#{kid}"), "keyid=#{kid}")
      end

      expect(response.code).to        eq("400")
      expect(error_code(response)).to eq("INVALID_SIGNATURE_INPUT")
    end
  end

  # sign_and_get signs and returns the request/response separately (unlike
  # linzer_http_get, which does both in one call), so this is the one case
  # that needs to touch the request *after* signing but *before* sending:
  # corrupting the signature itself. net_http_client still gives it the
  # same wire-level debug visibility as linzer_http_get's `debug:` option.
  it "rejects a request whose signature has been tampered with" do
    response = sign_and_get(test_jws_key_ed25519) do |request|
      chars = request["signature"].chars
      index = chars.index(":") + 1 # first byte of the base64 signature body
      chars[index] = (chars[index] == "A") ? "B" : "A"
      request["signature"] = chars.join
    end

    expect(response.code).to        eq("400")
    expect(error_code(response)).to eq("VERIFICATION_FAILED")
  end
end
