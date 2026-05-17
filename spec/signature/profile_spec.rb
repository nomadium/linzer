# frozen_string_literal: true

RSpec.describe Linzer::Signature::Profile do
  describe ".resolve" do
    subject(:resolve_profile) { described_class.resolve(profile) }

    context "when profile is nil" do
      let(:profile) { nil }

      it "returns nil" do
        expect(resolve_profile).to be_nil
      end
    end

    context "when profile is a Profile::Base instance" do
      let(:profile) { Linzer::Signature::Profile::Base.new }

      it "returns the profile instance unchanged" do
        expect(resolve_profile).to eq(profile)
      end
    end

    context "when profile is :web_bot_auth" do
      let(:profile) { :web_bot_auth }

      it "returns the default WebBotAuth profile" do
        expect(resolve_profile).to be_a(Linzer::Signature::Profile::WebBotAuth)
        expect(resolve_profile.params).to eq(:recommended)
        expect(resolve_profile.nonce).to  eq(:generate)
        expect(resolve_profile.agent).to  be_nil
      end
    end

    context "when profile is an unsupported symbol" do
      let(:profile) { :my_profile }

      it "raises a Linzer::Error" do
        expect { resolve_profile }
          .to raise_error(
            Linzer::Error,
            "Unknown/unsupported signing profile!"
          )
      end
    end

    context "when profile is an unsupported object" do
      let(:profile) { Object.new }

      it "raises a Linzer::Error" do
        expect { resolve_profile }
          .to raise_error(
            Linzer::Error,
            "Unknown/unsupported signing profile!"
          )
      end
    end
  end

  describe ".web_bot_auth" do
    subject(:profile) { described_class.web_bot_auth(**options) }

    let(:options) do
      {
        params: :recommended,
        nonce:  :generate,
        agent:  "https://example.com/bot"
      }
    end

    it "constructs a WebBotAuth profile with given options" do
      expect(Linzer::Signature::Profile::WebBotAuth)
        .to receive(:new)
        .with(**options)
        .and_call_original

      expect(profile).to be_a(Linzer::Signature::Profile::WebBotAuth)
    end

    it "passes through initializer options correctly" do
      instance = profile

      expect(instance.params).to eq(:recommended)
      expect(instance.nonce).to  eq(:generate)
      expect(instance.agent).to  eq("https://example.com/bot")
    end

    context "when no options are provided" do
      let(:options) { {} }

      it "uses defaults defined by WebBotAuth" do
        instance = profile

        expect(instance.params).to eq(:recommended)
        expect(instance.nonce).to  eq(:generate)
        expect(instance.agent).to  be_nil
      end
    end
  end
end
