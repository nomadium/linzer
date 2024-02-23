# Linzer

Linzer is a Ruby library for [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421.html).

## Install

Add the following line to your `Gemfile`:

```ruby
gem "linzer"
```

Or just `gem install linzer`.

## Usage

### To sign a HTTP message:

```ruby
key = Linzer::Key.new(material: OpenSSL::PKey::RSA.generate(2048), key_id: "my-test-key-rsa-pss")
# => #<struct Struct::Key material=#<OpenSSL::PKey::RSA:...

message = Linzer::Message.new(headers: {"date" => "Fri, 23 Feb 2024 17:57:23 GMT", "x-custom-header" => "foo"})
# => #<Linzer::Message:0x0000000111b592a0 @headers={"date"=>"Fri, 23 Feb 2024 17:57:23 GMT", ...

fields = %w[date x-custom-header])
signature = Linzer.sign(key, message, fields)
# => #<Linzer::Signature:0x0000000111f77ad0 ...

puts signature.to_h
{"signature"=>
  "sig1=:XQQnm4qyOdIa9yTebXzCQ4f7sXXnoe76D2g1gbFFc1DeqH...",
 "signature-input"=>"sig1=(\"date\" \"x-custom-header\");created=1708690868;keyid=\"my-test-key-rsa-pss\""}
```

### To verify a valid signature:

```ruby
pubkey = Linzer::Key.new(key_id: "some-key-rsa-pss", material: OpenSSL::PKey::RSA.new(test_key_rsa_pss))
# => #<struct Struct::Key material=#<OpenSSL::PKey::RSA:0x0000000106eade48 oid=rsaEncryption>, key_id="some-key-rsa-pss">

headers = {"signature-input" => "...", signature => "...", "date" => "Fri, 23 Feb 2024 13:18:15 GMT", "x-custom-header" => "bar"})

message = Linzer::Message.new(headers)
# => #<Linzer::Message:0x0000000111b592a0 @headers={"date"=>"Fri, 23 Feb 2024 13:18:15 GMT", ...

signature = Linzer::Signature.build(headers)
# => #<Linzer::Signature:0x0000000112396008 ...

Linzer.verify(pubkey, message, signature)
# => true
```

### What if an invalid signature if verified?

```ruby
result = Linzer.verify(pubkey, message, signature)
linzer/lib/linzer/verifier.rb:14:in `verify': Failed to verify message: Invalid signature. (Linzer::Error)
```

For now, to consult additional details, just take a look at source code and/or the unit tests.

Please note that is still early days, so only signatures RSASSA-PSS using SHA-512 like ones
described in the RFC are supported.

I'll be expanding the library to cover more functionality specified in the RFC
in subsequent releases.


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nomadium/linzer. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Linzer project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).
