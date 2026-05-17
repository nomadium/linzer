# frozen_string_literal: true

RSpec.describe Linzer::Signature::Profile::Base do
  describe "#apply" do
    subject(:apply_profile) { described_class.new.apply(ctx) }

    let(:ctx) { instance_double("Linzer::Signature::Context") }

    it "raises a Linzer::Error indicating subclasses must implement the method" do
      expect { apply_profile }
        .to raise_error(
          Linzer::Error,
          "Sub-classes are required to implement this method!"
        )
    end
  end
end
