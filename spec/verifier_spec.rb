# frozen_string_literal: true

RSpec.describe Linzer::Verifier do
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
    expect { described_class.verify(:key, nil, :signature) }
      .to raise_error(Linzer::Error, /cannot be null/)
  end

  it "cannot verify with a null key" do
    expect { described_class.verify(nil, :message, :signature) }
      .to raise_error(Linzer::Error, /Key.+cannot be null/)
  end

  it "cannot verify with a null signature" do
    expect { described_class.verify(:key, :message, nil) }
      .to raise_error(Linzer::Error, /Signature.+cannot be null/)
  end

  it "cannot verify a message with a missing component" do
    missing_component = "missing-component"
    request_data = {
      headers: {
        "content-digest"  => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-type"    => "application/json",
        "content-length"  => "18",
        "signature-input" => "sig1=(\"#{missing_component}\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    signature = Linzer::Signature.build(request_data[:headers])
    message = Linzer::Message.new(request_data)

    expect { described_class.verify(:key, message, signature) }
      .to raise_error(Linzer::Error, /Missing component.+#{missing_component}.*/)
  end

  it "cannot verify a message with duplicated component" do
    request_data = {
      headers: {
        "content-digest"  => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-type"    => "application/json",
        "content-length"  => "18",
        "x-dup"           => "duplicated value",
        "signature-input" => "sig1=(\"content-digest\" \"content-length\" \"x-dup\" \"x-dup\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    pubkey = Linzer::Key.new(key_id: "foo-key-rsa-pss", material: OpenSSL::PKey::RSA.generate(2048))
    signature = Linzer::Signature.build(request_data[:headers])
    message = Linzer::Message.new(request_data)

    expect { described_class.verify(pubkey, message, signature) }
      .to raise_error(Linzer::Error, /[dD]uplicated component/)
  end

  it "cannot verify a message with @signature-params component" do
    request_data = {
      headers: {
        "content-digest"  => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-type"    => "application/json",
        "content-length"  => "18",
        "x-dup"           => "duplicated value",
        "signature-input" => "sig1=(\"content-digest\" \"content-length\" \"@signature-params\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    pubkey = Linzer::Key.new(key_id: "foo-key-rsa-pss", material: OpenSSL::PKey::RSA.generate(2048))
    signature = Linzer::Signature.build(request_data[:headers])
    message = Linzer::Message.new(request_data)

    expect { described_class.verify(pubkey, message, signature) }
      .to raise_error(Linzer::Error, /[iI]nvalid component/)
  end

  it "fails to verify an invalid signature" do
    pubkey = Linzer::Key.new(key_id: "test-key-rsa-pss", material: OpenSSL::PKey::RSA.new(test_key_rsa_pss))
    request_data = {
      http: {
        "method" => "POST",
        "host"   => "example.com",
        "path"   => "/foo"
      },
      headers: {
        "host"            => "example.com",
        "date"            => "Tue, 20 Apr 2021 02:07:55 GMT",
        "content-type"    => "application/json",
        "content-digest"  => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-length"  => "18",
        "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature"       => "sig1=:pjVHGLiUCUEWQRfHoTIojBC/RdqV2EvaCbugKjHfFjj/YLMQfvjQOu2OPUdjNIRHwIuE+H+mdxcBUwBdamFuYvHWGC15l5ImSa0RFoqrhno+n51pK++FtRbkdyvqRnvPPOFIbDuaL//NETFHqO1aPuWoAeiEptNTKBbK2aej0LOaBJjGKYikpnAsK0A/4Yq0h3RpcOe09f1dLalM24ijcRGF7VzRuJwTgswNn9Sr1Tmg+0badt4NQHgMlsHHrAvLYfGueKggypRISgvAdnBpmYqgPWArqqNTVOHqzd3H+4tPUVFrt7AdeHevmIAsh9e2WzwUCnpSd73ZZGFQbWHqsQ==:"
      }
    }
    signature = Linzer::Signature.build(request_data[:headers])
    message   = Linzer::Message.new(request_data)

    expect { described_class.verify(pubkey, message, signature) }
      .to raise_error(Linzer::Error, /Invalid signature/)
  end

  # Example from section 3.2 Verifying a Signature
  it "verifies a valid signature" do
    pubkey = Linzer::Key.new(key_id: "test-key-rsa-pss", material: OpenSSL::PKey::RSA.new(test_key_rsa_pss))
    request_data = {
      http: {
        "method" => "POST",
        "host"   => "example.com",
        "path"   => "/foo"
      },
      headers: {
        "host"            => "example.com",
        "date"            => "Tue, 20 Apr 2021 02:07:55 GMT",
        "content-type"    => "application/json",
        "content-digest"  => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-length"  => "18",
        "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
      }
    }
    signature = Linzer::Signature.build(request_data[:headers])
    message = Linzer::Message.new(request_data)

    expect(described_class.verify(pubkey, message, signature)).to eq(true)
  end
end
