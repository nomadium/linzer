# frozen_string_literal: true

RSpec.describe Linzer::Message::Adapter::Generic::Request do
  describe "#attach!" do
    let(:adapter) { described_class.new(request) }

    context "no signature is present" do
      let(:request) do
        req = Net::HTTP::Get.new(URI("http://example.org/baz"))
        req["Content-Type"] = "application/json"
        req["User-Agent"] = "some_app"
        req
      end

      it "attaches a signature header to the message" do
        signature = Linzer::Signature.build({
          "Signature" => "sig1=:1aDqxoJQmUrtGsdqi7djQ3q9+I5Uty6EJZInXxASWzrl0kZeW+oNHRE92i3bDSoFuetq4yqtN0CXDQ0Qj+5XAQ==:",
          "Signature-Input" => "sig1=(\"@method\" \"@path\" \"content-type\");created=1777396187"
        })

        adapter.attach!(signature)

        expect(adapter.header("signature")).to       include("sig1")
        expect(adapter.header("signature-input")).to include("sig1")
      end

      context "and with additional headers to attach" do
        it "attaches a signature header and additional headers to the message" do
          signature = Linzer::Signature.build({
            "Signature" => "sig1=:1aDqxoJQmUrtGsdqi7djQ3q9+I5Uty6EJZInXxASWzrl0kZeW+oNHRE92i3bDSoFuetq4yqtN0CXDQ0Qj+5XAQ==:",
            "Signature-Input" => "sig1=(\"@method\" \"@path\" \"content-type\");created=1777396187"
          })

          adapter.attach!(signature, additional_headers: {"additional" => "value"})

          expect(adapter.header("signature")).to       include("sig1")
          expect(adapter.header("signature-input")).to include("sig1")
          expect(adapter.header("additional")).to      eq("value")
          expect(request["additional"]).to             eq("value")
        end
      end
    end

    # RFC 9421 Section 4.3 allows multiple signatures on a single message.
    # Each signature has a distinct label (e.g. "sig1", "sig2").
    # When a second signature is attached, the existing signature MUST be
    # preserved, not overwritten.
    #
    context "already has a signature" do
      let(:request) do
        req = Net::HTTP::Post.new(URI("http://example.org/foo"))
        req["Content-Type"] = "application/json"
        req["X-Custom"] = "value"
        req["Signature"] = "sig1=:gFYMaQPPRxe2c2H1ThJZrUxxRaZwE7Fku+8RVdZdMWvwX/PVZDeGn6cDgkLD6VlH/1iMCZE1o/Rqd4hFf2kOAQ==:",
          req["Signature-Input"] = "sig1=(\"@method\" \"@path\" \"content-type\");created=1777389498"
        req
      end

      it "preserves the first signature when a second signature is added" do
        expect(adapter.header("signature")).to       include("sig1")
        expect(adapter.header("signature-input")).to include("sig1")

        signature2 = Linzer::Signature.build({
          "Signature" => "sig2=:PTanu5dh8H1XjWkyjmetlqpXhGhG8poTiNUdcOJmIbxyACX0zLiKGpVlC53nmwDE5D620lkW6eWgjOdL9sQKCg==:",
          "Signature-Input" => "sig2=(\"@method\" \"x-custom\");created=1777389517"
        })

        adapter.attach!(signature2)

        expect(adapter.header("signature")).to       include("sig1")
        expect(adapter.header("signature")).to       include("sig2")
        expect(adapter.header("signature-input")).to include("sig1")
        expect(adapter.header("signature-input")).to include("sig2")
      end
    end

    context "non-compliant RFC 9421 signature" do
      let(:request) do
        req = Net::HTTP::Get.new(URI("http://example.org/bar"))
        req["Content-Type"] = "text/plain"
        req["Signature-Input"] = "signed: true"
        req["X-Foo"] = "data"
        req
      end

      it "raises error" do
        signature2 = Linzer::Signature.build({
          "Signature" => "sig2=:zyT///WTYacQeOX7b4uEQA9Bpgj1JWAMA9bdemRK+G/B4BfYSU0qBnjkETEpppOcGeoWXxy/E0U/VdaTU+dNBg==:",
          "Signature-Input" => "sig2=(\"x-foo\" \"@path\" \"content-type\");created=1777393781"
        })

        expect { adapter.attach!(signature2) }
          .to raise_error(Linzer::Error, /invalid/)
      end
    end

    context "signature with the same label" do
      let(:request) do
        uri = URI("https://example.com/test")
        req = Net::HTTP::Post.new(uri)
        req["Content-Type"] = "application/json"
        req["Signature"] = "sig1=:oQI4VsBVHQg1aOgkWf7HwI33z+Ot/6WQ5myQ2r3FGi4hdNWK/cF+fwbnfGUx2dmum4uGSrpxNEwjM+/KrCi6Cw==:"
        req["Signature-Input"] = "sig1=(\"@method\" \"@path\" \"content-type\");created=1777395448"
        req
      end

      it "overwrites the existing signature when using the same label" do
        first_sig = request["signature"]

        signature2 = Linzer::Signature.build({
          "Signature" => "sig1=:dFy9feQ+Y2Mo5QDTxl8/1XUFJqN4miw1lo4LCoeMirSGKt9f3h+Y6zroVoNAYR9nWf+RB/ChgMf6sWRAvDAtDQ==:",
          "Signature-Input" => "sig1=(\"@method\" \"x-custom\");created=1777395948"
        })

        adapter.attach!(signature2)

        second_sig = request["signature"]

        expect(second_sig).to_not eq(first_sig)

        # There should be exactly one "sig1" entry, not two
        sig_headers = request.each_header.to_h.slice("signature", "signature-input")
        parsed = Starry.parse_dictionary(sig_headers["signature"])

        expect(parsed.keys).to eq(["sig1"])
      end
    end
  end
end
