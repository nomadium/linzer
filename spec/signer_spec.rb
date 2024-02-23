# frozen_string_literal: true

RSpec.describe Linzer::Signer do
  let(:verifier) { Linzer::Verifier }

  let(:test_key_rsa_pss) do
    <<~EOS
      -----BEGIN PRIVATE KEY-----
      MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
      P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
      3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
      FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
      AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
      9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
      c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
      pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
      aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
      XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
      HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
      2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
      RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
      DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
      vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
      rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
      4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
      FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
      OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
      NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
      NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
      3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
      t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
      dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
      S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
      rOjr9w349JooGXhOxbu8nOxX
      -----END PRIVATE KEY-----
    EOS
  end

  it "cannot sign a null message" do
    expect { described_class.sign(:key, nil, []) }
      .to raise_error(Linzer::Error, /cannot be null/)
  end

  it "cannot sign a message with a null key" do
    expect { described_class.sign(nil, :message, []) }
      .to raise_error(Linzer::Error, /.+cannot be signed.+null key.*/)
  end

  it "cannot sign a message with a missing component" do
    request_data = {headers: {"header1" => "foo", "header2" => 10}}
    message      = Linzer::Message.new(request_data)
    expect { described_class.sign(:key, message, %w[header1 header2 missing]) }
      .to raise_error(Linzer::Error, /is not present in message/)
  end

  it "cannot sign a message with a duplicated component" do
    request_data = {headers: {"header1" => "foo", "header2" => 10}}
    message      = Linzer::Message.new(request_data)
    expect { described_class.sign(:key, message, %w[header1 header2 header2]) }
      .to raise_error(Linzer::Error, /[dD]uplicated component/)
  end

  it "cannot sign a message with a @signature-params component" do
    request_data = {headers: {"header1" => "foo", "header2" => 10}}
    message      = Linzer::Message.new(request_data)
    expect { described_class.sign(:key, message, %w[header1 header2 @signature-params]) }
      .to raise_error(Linzer::Error, /[iI]nvalid component/)
  end

  it "signs a message" do
    key = Linzer::Key.new(material: OpenSSL::PKey.read(test_key_rsa_pss), key_id: "test-key-rsa-pss")
    request_data = {
      http: {
        "method" => "POST",
        "host"   => "example.com",
        "path"   => "/foo"
      },
      headers: {
        "host"           => "example.com",
        "date"           => "Tue, 20 Apr 2021 02:07:55 GMT",
        "content-type"   => "application/json",
        "content-digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "content-length" => "18"
      }
    }

    message        = Linzer::Message.new(request_data)
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

    # XXX: Ideally, instead of having to do this it would be preferable
    # to call test_key_rsa_pss.public_key or key.public_to_pem
    test_key_rsa_pss_pub = <<~EOS
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

    # XXX: ideally this should work, but it doesn't with RSA-PSS keys... :(
    # that's why above declaration is required.
    # to-do: track this issue: https://github.com/ruby/openssl/issues/715
    # pubkey = Linzer::Key.new(key_id: parameters[:keyid, material: OpenSSL::PKey.read(key.public_to_pem))
    pubkey = Linzer::Key.new(key_id: parameters[:keyid], material: OpenSSL::PKey::RSA.new(test_key_rsa_pss_pub))

    expect(verifier.verify(pubkey, message, signature)).to eq(true)
  end
end
