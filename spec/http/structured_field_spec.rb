# frozen_string_literal: true

RSpec.describe Linzer::HTTP::StructuredField do
  describe ".parse_dictionary" do
    let(:input) { "sig1=:AQIDBA==:" }

    it "delegates to Starry.parse_dictionary" do
      expect(Starry)
        .to receive(:parse_dictionary)
        .with(input)

      described_class.parse_dictionary(input)
    end

    it "returns the parsed dictionary" do
      result = described_class.parse_dictionary(input)

      expect(result).to      be_a(Hash)
      expect(result.keys).to eq(["sig1"])
    end

    it "raises Linzer::Error on parse failure" do
      allow(Starry)
        .to receive(:parse_dictionary)
        .and_raise(StandardError.new("boom"))

      expect { described_class.parse_dictionary("invalid") }
        .to raise_error(Linzer::Error, "Cannot parse field!")
    end

    it "includes the field name in raised errors" do
      allow(Starry)
        .to receive(:parse_dictionary)
        .and_raise(StandardError.new("boom"))

      expect { described_class.parse_dictionary("invalid", field_name: "signature-input") }
        .to raise_error(Linzer::Error, 'Cannot parse "signature-input" field!')
    end
  end

  describe ".parse_item" do
    let(:input) { '"@method"' }

    it "delegates to Starry.parse_item" do
      expect(Starry)
        .to receive(:parse_item)
        .with(input)

      described_class.parse_item(input)
    end

    it "returns a parsed item" do
      item = described_class.parse_item(input)

      expect(item).to       be_a(Starry::Item)
      expect(item.value).to eq("@method")
    end

    it "raises Linzer::Error on invalid items" do
      allow(Starry)
        .to receive(:parse_item)
        .and_raise(StandardError.new("boom"))

      expect { described_class.parse_item("bad") }
        .to raise_error(Linzer::Error, "Invalid/unparseable HTTP field item")
    end
  end

  describe ".parse_list" do
    let(:input) { '("date" "host")' }

    it "delegates to Starry.parse_list" do
      expect(Starry)
        .to receive(:parse_list)
        .with(input)

      described_class.parse_list(input)
    end

    it "returns parsed list values" do
      result = described_class.parse_list(input)

      expect(result).to       be_an(Array)
      expect(result.first).to be_a(Starry::InnerList)
    end

    it "raises Linzer::Error on invalid lists" do
      allow(Starry)
        .to receive(:parse_list)
        .and_raise(StandardError.new("boom"))

      expect { described_class.parse_list("bad") }
        .to raise_error(Linzer::Error, "Invalid/unparseable HTTP field list")
    end
  end

  describe ".serialize_dictionary" do
    let(:value) { {"foo" => "bar"} }

    it "delegates to Starry.serialize_dictionary" do
      expect(Starry)
        .to receive(:serialize_dictionary)
        .with(value)

      described_class.serialize_dictionary(value)
    end

    it "serializes dictionaries" do
      expect(described_class.serialize_dictionary(value)).to eq('foo="bar"')
    end

    it "wraps serialization errors" do
      allow(Starry)
        .to receive(:serialize_dictionary)
        .and_raise(Starry::SerializeError.new("boom"))

      expect { described_class.serialize_dictionary(value) }
        .to raise_error(Linzer::Error, "boom")
    end
  end

  describe ".serialize_list" do
    let(:value) { ["foo", "bar"] }

    it "delegates to Starry.serialize_list" do
      expect(Starry)
        .to receive(:serialize_list)
        .with(value)

      described_class.serialize_list(value)
    end

    it "serializes lists" do
      expect(described_class.serialize_list(value)).to eq('"foo", "bar"')
    end

    it "wraps serialization errors" do
      allow(Starry)
        .to receive(:serialize_list)
        .and_raise(StandardError.new("boom"))

      expect { described_class.serialize_list(value) }
        .to raise_error(Linzer::Error, "boom")
    end
  end

  describe ".serialize_item" do
    subject(:serialize_item) { described_class.serialize_item(item) }

    let(:item) { "hello" }

    it "delegates to Starry.serialize_item" do
      expect(Starry).to receive(:serialize_item)
        .with(item)
        .and_return('"hello"')

      serialize_item
    end

    it "returns the serialized item" do
      allow(Starry).to receive(:serialize_item)
        .with(item)
        .and_return('"hello"')

      expect(serialize_item).to eq('"hello"')
    end

    context "when Starry raises SerializeError" do
      let(:starry_error) do
        Starry::SerializeError.new("unable to serialize item")
      end

      before do
        allow(Starry).to receive(:serialize_item)
          .with(item)
          .and_raise(starry_error)
      end

      it "raises Linzer::Error with the same message" do
        expect { serialize_item }
          .to raise_error(Linzer::Error, "unable to serialize item")
      end

      it "preserves the original exception as the cause" do
        expect do
          serialize_item
        rescue Linzer::Error => ex
          expect(ex.cause).to be(starry_error)
        end.not_to raise_error
      end
    end
  end

  describe ".serialize" do
    let(:value) { {"foo" => "bar"} }

    it "delegates to Starry.serialize" do
      expect(Starry)
        .to receive(:serialize)
        .with(value)

      described_class.serialize(value)
    end

    it "serializes objects" do
      expect(described_class.serialize(value)).to eq('foo="bar"')
    end

    it "wraps serialization errors" do
      allow(Starry)
        .to receive(:serialize)
        .and_raise(Starry::SerializeError.new("boom"))

      expect { described_class.serialize(value) }
        .to raise_error(Linzer::Error, "boom")
    end
  end

  describe ".serialize_parameters" do
    it "serializes integer parameters" do
      result = described_class.serialize_parameters(created: 1700000000)

      expect(result).to eq(";created=1700000000")
    end

    it "serializes string parameters" do
      result = described_class.serialize_parameters(keyid: "my-key")

      expect(result).to eq(';keyid="my-key"')
    end

    it "serializes mixed parameters" do
      result = described_class.serialize_parameters(
        created: 1700000000,
        keyid: "test-key",
        alg: "ed25519"
      )

      expect(result).to eq(';created=1700000000;keyid="test-key";alg="ed25519"')
    end

    it "returns an empty string for empty parameters" do
      expect(described_class.serialize_parameters({})).to eq("")
    end

    it "raises Linzer::Error on serialization failure" do
      expect { described_class.serialize_parameters(nil) }
        .to raise_error(Linzer::Error)
    end
  end
end
