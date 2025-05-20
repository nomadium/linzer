# frozen_string_literal: true

module Linzer
  class IncompleteAdapter < Linzer::Message::Adapter::Abstract
    def initialize(operation, **options)
      @operation = operation
    end
  end
end

RSpec.describe Linzer::Message::Adapter::Abstract do
  describe "#initialize" do
    it "cannot be instantiated" do
      request = Net::HTTP::Get.new(URI("http://example.org/something"))
      expect { described_class.new(request) }
        .to raise_error(Linzer::Error, /Cannot instantiate/)
    end
  end
  describe "#header" do
    context "when subclasses don't provide a complete implementation" do
      it "raises an error" do
        request = Net::HTTP::Get.new(URI("http://example.org/something"))
        adaptor = Linzer::IncompleteAdapter.new(request)
        expect { adaptor.header("signature") }
          .to raise_error(Linzer::Error, /required to implement this method/)
      end
    end
  end
  describe "#attach!" do
    context "when subclasses don't provide a complete implementation" do
      it "raises an error" do
        request = Net::HTTP::Get.new(URI("http://example.org/something"))
        adaptor = Linzer::IncompleteAdapter.new(request)
        expect { adaptor.attach!(:signature) }
          .to raise_error(Linzer::Error, /required to implement this method/)
      end
    end
  end
end
