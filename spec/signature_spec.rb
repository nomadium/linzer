# frozen_string_literal: true

RSpec.describe Linzer::Signature do
  it "cannot build signature through private constructor" do
    expect { described_class.new }
      .to raise_error(NoMethodError, /private method/)
  end

  it "cannot build signature from null request headers" do
    expect { described_class.build(nil) }
      .to raise_error(Linzer::Error, /cannot be null/)
  end

  it "cannot build signature from message with no headers" do
    expect { described_class.build({}) }
      .to raise_error(Linzer::Error, /No.+headers found/)
  end

  it "cannot build signature from a message missing signature field" do
    headers = {"signature-input" => "..."}
    expect { described_class.build(headers) }
      .to raise_error(Linzer::Error, /No "signature" header found/)
  end

  it "cannot build signature from a message missing signature-input field" do
    headers = {"signature" => "..."}
    expect { described_class.build(headers) }
      .to raise_error(Linzer::Error, /No "signature-input" header found/)
  end

  it "cannot build signature from invalid signature-input field" do
    headers = {
      "signature-input" => "...",
      "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
    }
    expect { described_class.build(headers) }
      .to raise_error(Linzer::Error, /Cannot parse .+signature-input.+ field/)
  end

  it "cannot build signature from unexpected signature-input field" do
    headers = {
      "signature-input" => "sig1=\"foo\"",
      "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
    }
    expect { described_class.build(headers) }
      .to raise_error(Linzer::Error, /Unexpected value for covered components/)
  end

  it "cannot build signature from a message with invalid signature field" do
    headers = {
      "signature-input" => 'sig1=("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"',
      "signature"       => "..."
    }
    expect { described_class.build(headers) }
      .to raise_error(Linzer::Error, /Cannot parse .+signature.+ field/)
  end

  it "cannot build signature from a message with more 1 signature if no label is given" do
    headers = {
      "signature-input" => 'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
      "signature" => "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"
    }
    expect { described_class.build(headers) }
      .to raise_error(Linzer::Error, /Multiple signatures/)
  end

  it "builds signature from a message with more than 1 signature if a label to select is given" do
    headers = {
      "signature-input" => 'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
      "signature" => "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"
    }
    label     = "proxy_sig"
    signature = described_class.build(headers, label: label)
    expect(signature.label).to eq(label)
  end

  it "cannot build signature from a message with signature label not found in input" do
    headers = {
      "signature-input" => 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
      "signature" => "sig-not-found=:d2pmTvmbncD3x==:"
    }
    expect { described_class.build(headers) }
      .to raise_error(Linzer::Error, /Signature.+not found/)
  end

  it "cannot build signature from a message with a signature label not found in headers" do
    headers = {
      "signature-input" => 'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256"',
      "signature" => "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:"
    }
    expect { described_class.build(headers, label: "not_found") }
      .to raise_error(Linzer::Error, /Signature.+not found/)
  end

  it "builds signature from a message with a valid signature headers" do
    headers = {
      "signature-input" => 'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256"',
      "signature" => "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:"
    }
    signature = described_class.build(headers)
    expect(signature).to be_a Linzer::Signature
  end

  it "builds signature from a message with a valid signature when label is explicitly indicated and found" do
    headers = {
      "signature-input" => 'proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
      "signature" => "proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"
    }
    label     = "proxy_sig"
    signature = described_class.build(headers, label: label)
    expect(signature.label).to eq(label)
  end
end
