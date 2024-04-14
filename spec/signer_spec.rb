# frozen_string_literal: true

RSpec.describe Linzer::Signer do
  let(:verifier) { Linzer::Verifier }

  let(:request_data) { Linzer::RFC9421::Examples.test_request_data }

  let(:request) do
    path = request_data[:http]["path"]
    Linzer.new_request(:post, path, {}, request_data[:headers])
  end

  let(:test_key_rsa_pss)     { Linzer::RFC9421::Examples.test_key_rsa_pss      }
  let(:test_key_rsa_pss_pub) { Linzer::RFC9421::Examples.test_key_rsa_pss_pub  }

  it "cannot sign a null message" do
    expect { described_class.sign(:key, nil, []) }
      .to raise_error(Linzer::Error, /null value/)
  end

  it "cannot sign a message with a null key" do
    expect { described_class.sign(nil, :message, []) }
      .to raise_error(Linzer::Error, /null key.*/)
  end

  it "cannot sign a message with null components" do
    expect { described_class.sign(:key, :message, nil) }
      .to raise_error(Linzer::Error, /null component/)
  end

  it "cannot sign a message with a missing component" do
    request_data = {headers: {"header1" => "foo", "header2" => 10}}
    path         = "/foo"
    request      = Linzer.new_request(:post, path, {}, request_data[:headers])
    message      = Linzer::Message.new(request)

    expect { described_class.sign(:key, message, %w[header1 header2 missing]) }
      .to raise_error(Linzer::Error, /[Mm]issing component in message/)
  end

  it "cannot sign a message with a duplicated component, example 1" do
    request_data = {headers: {"header1" => "foo", "header2" => 10}}
    path         = "/foo"
    request      = Linzer.new_request(:post, path, {}, request_data[:headers])
    message      = Linzer::Message.new(request)

    expect { described_class.sign(:key, message, %w[header1 header2 header2]) }
      .to raise_error(Linzer::Error, /[dD]uplicated component/)
  end

  it "cannot sign a message with a duplicated component, example 2" do
    example_dictionary = " a=1, b=2;x=1;y=2, c=(a   b    c), d"
    request_headers = {"Header1" => "foo", "Header2" => example_dictionary}
    request_data = {headers: request_headers}
    path         = "/foo"
    request      = Linzer.new_request(:post, path, {}, request_data[:headers])
    response     = Linzer.new_response(nil, 200, {"Header3" => "three"})
    message      = Linzer::Message.new(response, attached_request: request)

    expect { described_class.sign(:key, message, %w[header3 header2;bs;req header2;req;bs]) }
      .to raise_error(Linzer::Error, /[dD]uplicated component/)
  end

  it "cannot sign a message with a @signature-params component" do
    request_data = {headers: {"header1" => "foo", "header2" => 10}}
    path         = "/foo"
    request      = Linzer.new_request(:post, path, {}, request_data[:headers])
    components   = %w[header1 header2 @signature-params]
    message      = Linzer::Message.new(request)

    expect { described_class.sign(:key, message, components) }
      .to raise_error(Linzer::Error, /[iI]nvalid component/)
  end

  it "signs a message" do
    key_id = "test-key-rsa-pss"
    key = Linzer.new_rsa_pss_sha512_key(test_key_rsa_pss, key_id)

    message        = Linzer::Message.new(request)
    components     = %w[@method @authority @path content-digest content-length content-type].freeze
    unix_timestamp = 1618884473
    label          = Linzer::Signer.default_label
    parameters     = {created: unix_timestamp, keyid: key.key_id}
    signature      = described_class.sign(key, message, components, parameters)

    # RSA-PSS signature result is not deterministic,
    # we can't test for specific values, only its properties

    expect(signature.components).to            eq(components)
    expect(signature.parameters["created"]).to eq(parameters[:created])
    expect(signature.parameters["keyid"]).to   eq(parameters[:keyid])
    expect(signature.label).to                 eq(label)

    # to test if the signature is valid, we use the public key and build
    # a verifier to test if the result can be successfully verified

    # XXX: ideally this should work, but it doesn't with RSA-PSS keys... :(
    # to-do: track this issue: https://github.com/ruby/openssl/issues/715
    # pubkey = Linzer::new_rsa_pss_sha512_public_key(key.public_to_pem, parameters[:keyid])
    pubkey = Linzer.new_rsa_pss_sha512_public_key(test_key_rsa_pss_pub, key_id)

    expect(verifier.verify(pubkey, message, signature)).to eq(true)
  end

  # XXX: to-do: fix code duplication for this test
  it "signs a message, header names are capitalized" do
    key_id = "test-key-rsa-pss"
    key = Linzer.new_rsa_pss_sha512_key(test_key_rsa_pss, key_id)

    # example with capitalized header names
    headers =                         # => {"Host"=>"example.com",
      request_data[:headers]          #     "Date"=>"Tue, 20 Apr 2021 ...",
        .transform_keys(&:capitalize) #     "Content-Type"=>"application/json",
        .transform_keys { |k| k.gsub(/-([a-z]{1})/) { |s| s.upcase } }

    updated_request_data = {}
    updated_request_data[:http]    = request_data[:http]
    updated_request_data[:headers] = headers
    path = updated_request_data[:http]["path"]
    request = Linzer.new_request(:post, path, {}, updated_request_data[:headers])

    message        = Linzer::Message.new(request)
    components     = %w[@method @authority @path content-digest content-length content-type].freeze
    unix_timestamp = 1618884473
    label          = Linzer::Signer.default_label
    parameters     = {created: unix_timestamp, keyid: key.key_id}
    signature      = described_class.sign(key, message, components, parameters)

    # RSA-PSS signature result is not deterministic,
    # we can't test for specific values, only its properties

    expect(signature.components).to            eq(components)
    expect(signature.parameters["created"]).to eq(parameters[:created])
    expect(signature.parameters["keyid"]).to   eq(parameters[:keyid])
    expect(signature.label).to                 eq(label)

    # to test if the signature is valid, we use the public key and build
    # a verifier to test if the result can be successfully verified

    # XXX: ideally this should work, but it doesn't with RSA-PSS keys... :(
    # to-do: track this issue: https://github.com/ruby/openssl/issues/715
    # pubkey = Linzer::new_rsa_pss_sha512_public_key(key.public_to_pem, parameters[:keyid])
    pubkey = Linzer.new_rsa_pss_sha512_public_key(test_key_rsa_pss_pub, key_id)

    expect(verifier.verify(pubkey, message, signature)).to eq(true)
  end
end
