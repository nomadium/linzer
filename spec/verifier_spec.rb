# frozen_string_literal: true

RSpec.describe Linzer::Verifier do
  let(:verifier) { Linzer::Verifier.new }

  let(:test_key_rsa_pss) do
    <<~EOS
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
      +QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
      oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
      gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
      Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
      aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
      2wIDAQAB                                                    
      -----END PUBLIC KEY-----            
    EOS
  end

  it "cannot verify a null message" do
    expect { verifier.verify(nil) }
      .to raise_error(Linzer::Error, /cannot be null/)
  end

  it "cannot verify an empty message" do
    expect { verifier.verify({}) }
      .to raise_error(Linzer::Error, /cannot be empty/)
  end

  it "cannot verify a message without signature-input field" do
    request_data = {headers: {"signature" => "..."}}
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /cannot be incomplete/)
  end

  it "cannot verify a message without signature" do
    request_data = {headers: {"signature-input" => "..."}}
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /has no signature to verify/)
  end

  it "cannot verify a message with invalid signature-input field" do
    request_data = {
      headers: {
        "signature-input" => "...",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /Cannot parse .+signature-input.+ field/)
  end

  it "cannot verify a message with invalid signature field" do
    request_data = {
      headers: {
        "signature-input" => 'sig1=("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"',
        "signature" => "..."
      }
    }
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /Cannot parse .+signature.+ field/)
  end

  # XXX: let's revisit the use of of multiple signatures later
  it "cannot verify a message with more than 2 signatures" do
    request_data = {
      headers: {
        "signature-input" => 'sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
        "signature" => "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"
      }
    }
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /more than 1.+are not supported/)
  end

  it "cannot verify a message with signature label not found in input" do
    request_data = {
      headers: {
        "signature-input" => 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
        "signature" => "sig-not-found=:d2pmTvmbncD3x==:"
      }
    }
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /Signature.+not found/)
  end

  it "cannot verify a message with an unknown key" do
    key_id = "unknown-key-rsa-pss"
    request_data = {
      headers: {
        "signature-input" => "sig1=();created=1618884473;keyid=\"#{key_id}\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /Key.+not found.+#{key_id}.*/)
  end

  it "cannot verify a message without \"keyid\" parameter" do
    request_data = {
      headers: {
        "signature-input" => 'sig1=();created=1618884473;nonce="b3k2pp5k7z-50gnwp.yemd"',
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /Key.+not found$/)
  end

  it "cannot verify a message with a missing component" do
    pubkeys = {"test-key-rsa-pss" => "..."}
    missing_component = "missing-component"
    verifier = Linzer::Verifier.new(pubkeys)

    request_data = {
      headers: {
        "content-digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-type" => "application/json",
        "content-length" => "18",
        "signature-input" => "sig1=(\"#{missing_component}\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    message = Linzer::Message.new(request_data)

    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /Missing component.+#{missing_component}.*/)
  end

  it "fails to verify an invalid signature" do
    pubkeys = {"test-key-rsa-pss" => OpenSSL::PKey::RSA.new(test_key_rsa_pss)}
    verifier = Linzer::Verifier.new(pubkeys)
    request_data = {
      http: {
        "method" => "POST",
        "host" => "example.com",
        "path" => "/foo"
      },
      headers: {
        "host" => "example.com",
        "date" => "Tue, 20 Apr 2021 02:07:55 GMT",
        "content-type" => "application/json",
        "content-digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-length" => "18",
        "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature" => "sig1=:pjVHGLiUCUEWQRfHoTIojBC/RdqV2EvaCbugKjHfFjj/YLMQfvjQOu2OPUdjNIRHwIuE+H+mdxcBUwBdamFuYvHWGC15l5ImSa0RFoqrhno+n51pK++FtRbkdyvqRnvPPOFIbDuaL//NETFHqO1aPuWoAeiEptNTKBbK2aej0LOaBJjGKYikpnAsK0A/4Yq0h3RpcOe09f1dLalM24ijcRGF7VzRuJwTgswNn9Sr1Tmg+0badt4NQHgMlsHHrAvLYfGueKggypRISgvAdnBpmYqgPWArqqNTVOHqzd3H+4tPUVFrt7AdeHevmIAsh9e2WzwUCnpSd73ZZGFQbWHqsQ==:"
      }
    }
    message = Linzer::Message.new(request_data)
    expect { verifier.verify(message) }
      .to raise_error(Linzer::Error, /Invalid signature/)
  end

  # Example from section 3.2 Verifying a Signature
  it "verifies a valid signature" do
    pubkeys = {"test-key-rsa-pss" => OpenSSL::PKey::RSA.new(test_key_rsa_pss)}
    verifier = Linzer::Verifier.new(pubkeys)
    request_data = {
      http: {
        "method" => "POST",
        "host" => "example.com",
        "path" => "/foo"
      },
      headers: {
        "host" => "example.com",
        "date" => "Tue, 20 Apr 2021 02:07:55 GMT",
        "content-type" => "application/json",
        "content-digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-length" => "18",
        "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    message = Linzer::Message.new(request_data)
    expect(verifier.verify(message)).to eq(true)
  end
end
