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
end
