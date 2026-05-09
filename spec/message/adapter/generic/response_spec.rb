RSpec.describe Linzer::Message::Adapter::Generic::Response do
  describe "#attach!" do
    let(:adapter) { described_class.new(response) }

    context "no signature is present" do
      let(:response) do
        resp = Net::HTTPOK.new("1.1", "200", "OK")
        resp["Content-Type"] = "text/plain"
        resp["X-Resp"]       = "data"
        resp
      end

      it "attaches a signature header to the message" do
        signature = Linzer::Signature.build({
          "Signature" => "sig1=:Cyka+VA0rqBEG5SXqKajOqA4QqrLlOXWbLbJ6JQwI97gbYCOxaPRM1+JA+2sn1cTNfI+4gcaZGye4rKnN4A6Cg==:",
          "Signature-Input" => "sig1=(\"@status\" \"content-type\");created=1777398359"
        })

        adapter.attach!(signature)

        expect(adapter.header("signature")).to       include("sig1")
        expect(adapter.header("signature-input")).to include("sig1")
      end
    end

    # RFC 9421 Section 4.3 allows multiple signatures on a single message.
    # Each signature has a distinct label (e.g. "sig1", "sig2").
    # When a second signature is attached, the existing signature MUST be
    # preserved, not overwritten.
    #
    context "already has a signature" do
      let(:response) do
        resp = Net::HTTPOK.new("1.1", "200", "OK")
        resp["Content-Type"]    = "application/json"
        resp["X-Resp"]          = "data"
        resp["Signature"]       = "sig1=:EtgF5ld88dFjOEmyH5ps7bjrIyyRaazhAfrbxJg0SNBw/So+u7eSrRtHAtt6txLggXK2hDnDtiJawxhJMZcyDw==:"
        resp["Signature-Input"] = "sig1=(\"@status\" \"x-resp\");created=1777398359"
        resp
      end

      it "preserves the first signature when a second signature is added" do
        expect(adapter.header("signature")).to       include("sig1")
        expect(adapter.header("signature-input")).to include("sig1")

        signature2 = Linzer::Signature.build({
          "Signature" => "sig2=:rkFzM817Dtd9AHYeufBjXZw9sPKjq7BrLhJpCbFtQLnXKrK/WUnwmN2EaUpPWRWj25ffmguTYHFdbzsLyQrqDg==:",
          "Signature-Input" => "sig2=(\"@status\" \"content-type\");created=1777398391"
        })

        adapter.attach!(signature2)

        expect(adapter.header("signature")).to       include("sig1")
        expect(adapter.header("signature")).to       include("sig2")
        expect(adapter.header("signature-input")).to include("sig1")
        expect(adapter.header("signature-input")).to include("sig2")
      end
    end

    context "non-compliant RFC 9421 signature" do
      let(:response) do
        resp = Net::HTTPOK.new("1.1", "200", "OK")
        resp["Content-Type"]    = "application/json"
        resp["X-Resp"]          = "data"
        resp["Signature-Input"] = "signed: true"
        resp
      end

      xit "raises error" do
        signature2 = Linzer::Signature.build({
          "Signature" => "sig2=:xg36cZqE5o6kr4U1Oph3dqL3Y3TteOIC8QBTDQzvJEiug4NyyupEu6F75GWJcwBQjjEjDhQHnW5wN0H4dZ/uDA==:",
          "Signature-Input" => "sig2=(\"@status\" \"content-type\");created=1777398391"
        })

        expect { adapter.attach!(signature2) }
          .to raise_error(Linzer::Error, /invalid/)
      end
    end

    context "signature with the same label" do
      let(:response) do
        resp = Net::HTTPOK.new("1.1", "200", "OK")
        resp["Content-Type"]    = "text/plain"
        resp["X-Resp"]          = "data"
        resp["Signature"]       = "sig1=:zqDmr8f3ie1TJBSjT2YwUIC0zr+jgj9xSIHPbQ7OQ2ww0Ors+oPR5OTl6cj/VIQCNzVCsGh0obsUloFV2AnwDA==:"
        resp["Signature-Input"] = "sig1=(\"@status\" \"content-type\");created=1777398417"
        resp
      end

      it "overwrites the existing signature when using the same label" do
        first_sig = response["signature"]

        signature2 = Linzer::Signature.build({
          "Signature" => "sig1=:KIp9/5XG1RMn+2q/idCUfGaBSYVzGMoec+HNpfx/40Iq0cpoKHKXWbt2zO/ooHOYCOYo0J7xu+hrQPfwN2Q7AA==:",
          "Signature-Input" => "sig1=(\"@status\" \"content-type\");created=1777398417"
        })

        adapter.attach!(signature2)

        second_sig = response["signature"]

        expect(second_sig).to_not eq(first_sig)

        # There should be exactly one "sig1" entry, not two
        sig_headers = response.each_header.to_h.slice("signature", "signature-input")
        parsed = Starry.parse_dictionary(sig_headers["signature"])

        expect(parsed.keys).to eq(["sig1"])
      end
    end
  end
end
