# frozen_string_literal: true

RSpec.describe Linzer::Message::Field::Identifier do
  describe "#serialize" do
    it "returns serialized identifier for a message field, example 1" do
      identifier = described_class.new(field_name: "cache-control")
      expect(identifier.serialize).to eq('"cache-control"')
    end
    it "returns serialized identifier for a message field, example 2" do
      identifier = described_class.new(field_name: "@authority")
      expect(identifier.serialize).to eq('"@authority"')
    end
    it "returns serialized identifier for a message field, example 3" do
      identifier = described_class.new(field_name: "@signature-params")
      expect(identifier.serialize).to eq('"@signature-params"')
    end
    it "returns serialized identifier for a message field, example 4" do
      identifier = described_class.new(field_name: 'example-dictionary;key="foo"')
      expect(identifier.serialize).to eq('"example-dictionary";key="foo"')
    end
    it "raises error when an invalid identifier is provided" do
      identifier = described_class.new(field_name: "^%$@error-foo")
      expect { identifier.serialize }
        .to raise_error(Linzer::Error, /Invalid component identifier/)
    end
  end
end
