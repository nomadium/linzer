# frozen_string_literal: true

require "linzer/signature/profile/example"

RSpec.describe Linzer::Signature::Profile::Example do
  subject(:profile) do
    described_class.new(foo: foo, bar: bar)
  end

  let(:foo) { "foo-value" }
  let(:bar) { "bar-value" }

  describe "#initialize" do
    it "stores the provided configuration values" do
      expect(profile.instance_variable_get(:@foo)).to eq(foo)
      expect(profile.instance_variable_get(:@bar)).to eq(bar)
    end
  end

  describe "#apply" do
    let(:ctx) { instance_double("Linzer::Signature::Context") }

    it "does not raise an error" do
      expect { profile.apply(ctx) }.not_to raise_error
    end

    it "does not modify the context and just returns nil" do
      expect(profile.apply(ctx)).to be_nil
    end
  end
end
