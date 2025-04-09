# frozen_string_literal: true

RSpec.describe Linzer::Verifier do
  let(:request_data) { Linzer::RFC9421::Examples.test_request_data }

  let(:test_key_rsa_pss_pub) { Linzer::RFC9421::Examples.test_key_rsa_pss_pub  }

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

  it "cannot verify with an unexpected or invalid signature object" do
    expect { described_class.verify(:key, :message, :signature) }
      .to raise_error(Linzer::Error, /Signature is invalid/)
  end

  it "cannot verify a message with a missing component" do
    missing_component = "missing-component"
    signature_with_missing_component = {
      "signature-input" => "sig1=(\"#{missing_component}\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
      "signature"       => "sig1=:1ol7oGscodPV7z/4FuUerzklskHHz7M2VSaE+xBF5aUeAdzMp5eMBDl5cM+CVMO+x6svIEZj67/EBkicjeenSVF0JLF9pxc8FLJxUJyM6Ku3G/KQ+J4Kih4dd9DKl5s2ux2a5tdKtDNuL7GgAkLXRCoQwcEmCMMbt+CPTuW57rXtPm2Vd1MZzJHuwr37GSgj7tZ6EQJZPaZicxclRT7RrihFTEasTomAgSg0W4AFkBsELzYKGMGRSz8GdDZIAK2JQJs4/l21hHPSvu2zuAbWiQ22t9GwBQW3I3G7i1mMtNxcy7sJ9FbOM5SM96j9BI6LCtkZNsmU3ZnyPvZsPR4axA==:"
    }

    test_request_data = request_data.dup
    test_request_data[:headers].merge!(signature_with_missing_component)
    path = request_data[:http]["path"]
    request = Linzer.new_request(:post, path, {}, test_request_data[:headers])

    signature = Linzer::Signature.build(test_request_data[:headers])
    message = Linzer::Message.new(request)

    expect { described_class.verify(:key, message, signature) }
      .to raise_error(Linzer::Error, /Missing component.+#{missing_component}.*/)
  end

  it "cannot verify a message with duplicated component" do
    signature_with_duplicated_component = {
      "signature-input" => "sig1=(\"content-digest\" \"content-length\" \"content-type\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
      "signature"       => "sig1=:rBqsUrhky+qXVie2Q7ydrKOiq3MIMQdajc7qU+urk4nD8ziUkdcfpWQVGNOazsgBeORRF7C1AxQcp9AjS9sYNxD22eSIrPm1pXroLs5wWc25uVIzKhYBrCPs/lW0xEZDGRyj/Bi8GkNxImJkDrvBApIAmQgASMOqafdEMafbnlIbHQ3+K5dn3vxBOkNpL8on34YB9pWrv9Ghv2ZWkBqqYikaIub3nS4zhj+HpD14M9cnDHjwsN+iDbbcwnKC2wBz48YUvYxE/4FEJP4VU/D5ID7Q3h1vKJTX9Xo2XMqIW40I/rbj5kT2Wp4Q56XmXZpcsNUzwHNVa3Q2HR+0Q/ziyw==:"
    }
    test_request_data = request_data.dup
    test_request_data[:headers].merge!(signature_with_duplicated_component)
    path = request_data[:http]["path"]
    request = Linzer.new_request(:post, path, {}, test_request_data[:headers])

    pubkey = Linzer.generate_rsa_pss_sha512_key(2048, "foo-key-rsa-pss")
    signature = Linzer::Signature.build(test_request_data[:headers])
    message = Linzer::Message.new(request)

    expect { described_class.verify(pubkey, message, signature) }
      .to raise_error(Linzer::Error, /[dD]uplicated component/)
  end

  it "cannot verify a message with @signature-params component" do
    signature_with_invalid_component = {
      "signature-input" => "sig1=(\"content-digest\" \"content-length\" \"@signature-params\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
      "signature"       => "sig1=:kRAeUug8ffLM6RE5FfnH9mwQ+1zAJK9ORBp/rbO6u2HXuZbfQP863xo3texBklxWrgOAudCS4I3/7jkEhqEjP7vEJGI0tRSb1q7+PlnTtbANO1HDz2lSXn5KRVfELk+r5054V2IdvF1yYxstgkO8eYxkokkTyp+3v86xqpmP2DRPcVoG8b1jjSh8LraLD8jEBlDkprxdprRBhHVVMCFVmK+/y3/BrDVVpMJ/MdrjOkaNHjk8ASWXw2Imc+Gi/ZeTu26j+aqp295kaG3qyjiPnY93hcgZNo2J/x6Q4tdzBt3ljuN/OtYCL/PegCr3XpQMDrmGpfG1M8kVIph2z/aGig==:"
    }
    test_request_data = request_data.dup
    test_request_data[:headers].merge!(signature_with_invalid_component)
    path = request_data[:http]["path"]
    request = Linzer.new_request(:post, path, {}, test_request_data[:headers])

    pubkey = Linzer.generate_rsa_pss_sha512_key(2048, "foo-key-rsa-pss")
    signature = Linzer::Signature.build(test_request_data[:headers])
    message = Linzer::Message.new(request)

    expect { described_class.verify(pubkey, message, signature) }
      .to raise_error(Linzer::Error, /[iI]nvalid component/)
  end

  it "fails to verify an invalid signature" do
    invalid_signature = {
      "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
      "signature"       => "sig1=:O4NY94ZQb05YXnyJg8Jj2MiSWuq3Sthf/ii0EDbcn9PAyHapz56a5G4MXBkq4HDEcreY6BodYghaBMHblqXpS0CriibHPc6HcEmYB1ZX2VogtzIkLiv9qr6DGYWhdwkozGe6kt1tFr2PmXoV4GSt6Jl7BFYOGgTYHnUWaVHM+EVnJMUvx/Tu5fhXJE6bvXMfI2fWj8ecwXl+fA/pJSL2QhvwfDkLyTGR9UWkzlEmNLn27I0Y+XQAK/djzhQJ+tMHjtzgNx6qt/IRmsVr8LSUSZGh7A0kUmusVHu5DPydwScmBFDAvd/Jv+8RZLsW3ayAVR0Rqhkaqse5h9O/fP7Ieg==:"
    }
    test_request_data = request_data.dup
    test_request_data[:headers].merge!(invalid_signature)
    path = request_data[:http]["path"]
    request = Linzer.new_request(:post, path, {}, test_request_data[:headers])

    pubkey = Linzer.new_rsa_pss_sha512_key(test_key_rsa_pss_pub, "test-key-rsa-pss")

    signature = Linzer::Signature.build(test_request_data[:headers])
    message   = Linzer::Message.new(request)

    expect { described_class.verify(pubkey, message, signature) }
      .to raise_error(Linzer::Error, /Invalid signature/)
  end

  # Example from section 3.2 Verifying a Signature
  it "verifies a valid signature" do
    valid_signature = {
      "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
      "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
    }
    test_request_data = request_data.dup
    test_request_data[:headers].merge!(valid_signature)
    path = request_data[:http]["path"]
    request = Linzer.new_request(:post, path, {}, test_request_data[:headers])

    pubkey = Linzer.new_rsa_pss_sha512_key(test_key_rsa_pss_pub, "test-key-rsa-pss")
    signature = Linzer::Signature.build(test_request_data[:headers])
    message = Linzer::Message.new(request)

    expect(described_class.verify(pubkey, message, signature)).to eq(true)
  end

  # Example from section 3.2 Verifying a Signature
  # but with capitalized header names
  # XXX: to-do: fix code duplication for this test
  it "verifies a valid signature" do
    valid_signature = {
      "Signature-Input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
      "Signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
    }

    test_request_data = request_data.dup
    # example with capitalized header names
    test_request_data[:headers]      # => {"Host"=>"example.com",
      .transform_keys!(&:capitalize) #     "Date"=>"Tue, 20 Apr 2021 ...",
      .transform_keys! { |k| k.gsub(/-([a-z]{1})/) { |s| s.upcase } }
      .merge!(valid_signature)       #     "Content-Type"=>"application/json",

    path = request_data[:http]["path"]
    request = Linzer.new_request(:post, path, {}, test_request_data[:headers])

    pubkey = Linzer.new_rsa_pss_sha512_key(test_key_rsa_pss_pub, "test-key-rsa-pss")
    signature = Linzer::Signature.build(test_request_data[:headers])
    message = Linzer::Message.new(request)

    expect(described_class.verify(pubkey, message, signature)).to eq(true)
  end

  context "when passing the `no_older_than` parameter" do
    let(:test_request_data) do
      test_request_data = request_data.dup
      test_request_data[:headers].merge!(valid_signature)
      test_request_data
    end

    let(:message) do
      path = test_request_data[:http]["path"]
      request = Linzer.new_request(:post, path, {}, test_request_data[:headers])
      Linzer::Message.new(request)
    end
    let(:pubkey) do
      Linzer.new_rsa_pss_sha512_key(test_key_rsa_pss_pub, "test-key-rsa-pss")
    end
    let(:signature) do
      Linzer::Signature.build(test_request_data[:headers])
    end

    context "when `created` is present" do
      let(:valid_signature) do
        {
          "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\"",
          "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
        }
      end

      it "verifies `created` and passes when it is not too old" do
        age = Time.now.to_i - 1618884472
        expect(described_class.verify(pubkey, message, signature, no_older_than: age)).to eq true
      end

      it "verifies `created` and fails when it is too old" do
        expect { described_class.verify(pubkey, message, signature, no_older_than: 300) }
          .to raise_error(Linzer::Error, /Signature created more than 300 seconds ago/)
      end
    end

    context "when `created` is present but invalid" do
      let(:valid_signature) do
        {
          "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=\"something\";keyid=\"test-key-rsa-pss\"",
          "signature" => "sig1=:HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJsYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzTZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOrpIC49yXjj3ae6HRalVc/g==:"
        }
      end

      it "fails verification" do
        expect { described_class.verify(pubkey, message, signature, no_older_than: 300) }
          .to raise_error(Linzer::Error, /non-integer/)
      end
    end

    context "when `created` is missing" do
      let(:valid_signature) do
        {
          "signature-input" => "sig1=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");keyid=\"test-key-rsa-pss\"",
          "signature" => "sig1=:gUpR6HipAmj9/6XWb6/HRFkaZ9Su28KctBgK0z31XpqAz9WIKRPQGJ7p6u1mNo+NxfO1FG7e9hCoo+R4zZF+ExstI2mQKyhFeDi9Q3F9pyVlU0Z/AFdPJgBbFg2EmE8QQf/99pNPQFBrpl1ceTO1s8BEVPpodgV/7s9mIMXwAv+WG2kKq9lSKJzGYHe4mC8wlsfp35Vn/kdcmCr5EwFJ5z5Rh4EcluU+p5lJVwGZaKBpGxBWal5jtEEABfczEWJfnCf6g4XdR4aRl2qP/hiodQE80gAk9GBN08ra2PqckagBTr5VaJji3LmJRM8cpj6YSLJhsNqYWhdq2bKyYJ2aAA==:"
        }
      end

      it "fails verification" do
        expect { described_class.verify(pubkey, message, signature, no_older_than: 300) }
          .to raise_error(Linzer::Error, /Signature is missing the `created` parameter/)
      end
    end
  end
end
