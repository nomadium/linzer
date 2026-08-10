# frozen_string_literal: true

require "linzer/jws"

RSpec.describe Linzer::Signature::Profile::WebBotAuth do
  describe ".default" do
    subject(:profile) { described_class.default }

    it "returns a default configured profile instance" do
      expect(profile).to be_a(described_class)

      expect(profile.params).to eq(:recommended)
      expect(profile.nonce).to  eq(:generate)
    end
  end

  describe "#apply" do
    subject(:apply_profile) { profile.apply(ctx) }

    let(:profile) do
      described_class.new(
        params: params_mode,
        nonce:  nonce_mode,
        agent:  agent
      )
    end

    let(:params_mode) { :recommended }
    let(:nonce_mode)  { :generate }
    let(:agent)       { nil }

    let(:key) do
      Linzer::JWS.generate_key(algorithm: "EdDSA")
    end

    let(:message) do
      instance_double(
        "Linzer::Message",
        request?: true
      )
    end

    let(:components)      { [] }
    let(:params)          { {} }
    let(:overlay_headers) { {} }

    let(:ctx) do
      instance_double(
        "Linzer::Signature::Context",
        key:             key,
        message:         message,
        components:      components,
        params:          params,
        overlay_headers: overlay_headers
      )
    end

    before do
      allow(SecureRandom)
        .to receive(:urlsafe_base64)
        .with(64)
        .and_return("generated-nonce")
    end

    context "with default configuration" do
      it "adds recommended parameters" do
        apply_profile

        expect(params[:tag]).to     eq("web-bot-auth")
        expect(params[:keyid]).to   eq(key.jwk_thumbprint)
        expect(params[:expires]).to eq(Time.now.to_i + 3600)
      end

      it "adds a nonce" do
        apply_profile

        expect(params[:nonce]).to eq("generated-nonce")
      end

      it "ensures an auth component is covered" do
        apply_profile

        expect(components & %w[@authority @target-uri]).not_to be_empty
      end
    end

    context "when components already include a required auth component" do
      let(:components) { ["@authority"] }

      it "does not add another auth component" do
        apply_profile

        expect(components).to eq(["@authority"])
      end
    end

    context "when params already exist" do
      let(:params) do
        {
          expires: 123,
          tag:     "custom-tag",
          keyid:   "custom-keyid"
        }
      end

      it "does not overwrite existing params" do
        apply_profile

        expect(params[:expires]).to eq(123)
        expect(params[:tag]).to     eq("custom-tag")
        expect(params[:keyid]).to   eq("custom-keyid")
      end
    end

    context "when params mode is nil" do
      let(:params_mode) { nil }

      it "does not inject recommended params" do
        apply_profile

        expect(params).not_to have_key(:expires)
        expect(params).not_to have_key(:tag)
        expect(params).not_to have_key(:keyid)
      end
    end

    context "when nonce mode is nil" do
      let(:nonce_mode) { nil }

      it "does not generate a nonce" do
        apply_profile

        expect(params).not_to have_key(:nonce)
      end
    end

    context "when an agent is configured" do
      let(:agent) { "https://example.com/bot" }

      before do
        allow(message)
          .to receive(:[])
          .with("signature-agent")
          .and_return(nil)

        allow(Linzer::HTTP::StructuredField)
          .to receive(:serialize_dictionary)
          .with("sig1" => agent)
          .and_return('sig1="https://example.com/bot"')

        allow(Linzer::HTTP::StructuredField)
          .to receive(:serialize)
          .and_return('"signature-agent";key="sig1"')
      end

      let(:params) { {label: "sig1"} }

      it "injects the Signature-Agent header" do
        apply_profile

        expect(overlay_headers).to eq(
          "signature-agent" => 'sig1="https://example.com/bot"'
        )
      end

      it "adds the structured field to covered components" do
        apply_profile

        expect(components).to include('"signature-agent";key="sig1"')
      end
    end

    context "when the Signature-Agent header already matches" do
      let(:agent) { "https://example.com/bot" }

      before do
        allow(message)
          .to receive(:[])
          .with("signature-agent")
          .and_return(agent)
      end

      let(:params) { {label: "sig1"} }

      it "does not inject overlay headers" do
        apply_profile

        expect(overlay_headers).to be_empty
      end
    end

    context "when Starry serialization fails" do
      let(:agent) { "https://example.com/bot" }

      before do
        allow(message)
          .to receive(:[])
          .with("signature-agent")
          .and_return(nil)

        allow(Linzer::HTTP::StructuredField)
          .to receive(:serialize_dictionary)
          .and_raise(Linzer::Error.new("boom"))
      end

      let(:params) { {label: "sig1"} }

      it "raises a Linzer::Error" do
        expect { apply_profile }
          .to raise_error(Linzer::Error,
            "Invalid signature-agent header value!"
          )
      end
    end

    context "when the key is invalid" do
      let(:key) { Object.new }

      it "raises a Linzer::Error" do
        expect { apply_profile }
          .to raise_error(
            Linzer::Error,
            "Unsupported/invalid key!"
          )
      end
    end

    context "when the message is not a request" do
      before do
        allow(message)
          .to receive(:request?)
          .and_return(false)
      end

      it "raises a Linzer::Error" do
        expect { apply_profile }
          .to raise_error(
            Linzer::Error,
            "Web Bot Auth is defined only for requests!"
          )
      end
    end
  end
end
