# Linzer [![Latest Version][gem-badge]][gem-link] [![License: MIT][license-image]][license-link] [![CI Status][ci-image]][ci-link]

[gem-badge]: https://badge.fury.io/rb/linzer.svg
[gem-link]: https://rubygems.org/gems/linzer
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/nomadium/linzer/blob/master/LICENSE.txt
[ci-image]: https://github.com/nomadium/linzer/actions/workflows/main.yml/badge.svg?branch=master
[ci-link]: https://github.com/nomadium/linzer/actions/workflows/main.yml

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
key = Linzer.generate_ed25519_key
# => #<Linzer::Ed25519::Key:0x00000fe13e9bd208

headers = {
  "date" => "Fri, 23 Feb 2024 17:57:23 GMT",
  "x-custom-header" => "foo"
}

request = Linzer.new_request(:post, "/some_uri", {}, headers)
# => #<Rack::Request:0x0000000104c1c8c0
#       @env={"HTTP_DATE"=>"Fri, 23 Feb 2024 17:57:23 GMT", "HTTP_X_CUSTOM..."
#       @params=nil>

message = Linzer::Message.new(request)
# => #<Linzer::Message:0x0000000104afa960
#       @operation=#<Rack::Request:0x00000001049754a0
#       @env={"HTTP_DATE"=>"Fri, 23 Feb 2024 17:57:23 GMT", "HTTP_X_CUSTOM..."
#       @params=nil>>

fields = %w[date x-custom-header @method @path]

signature = Linzer.sign(key, message, fields)
# => #<Linzer::Signature:0x0000000111f77ad0 ...

pp signature.to_h
# => {"signature"=>"sig1=:Cv1TUCxUpX+5SVa7pH0Xh...",
#  "signature-input"=>"sig1=(\"date\" \"x-custom-header\" ..."}
```

### Use the message signature with any HTTP client:

```ruby
require "net/http"

http = Net::HTTP.new("localhost", 9292)
http.set_debug_output($stderr)
response = http.post("/some_uri", "data", headers.merge(signature.to_h))
# opening connection to localhost:9292...
# opened
# <- "POST /some_uri HTTP/1.1\r\n
# <- Date: Fri, 23 Feb 2024 17:57:23 GMT\r\n
# <- X-Custom-Header: foo\r\n
# <- Signature: sig1=:Cv1TUCxUpX+5SVa7pH0X...
# <- Signature-Input: sig1=(\"date\" \"x-custom-header\" \"@method\"...
# <- Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\r\n
# <- Accept: */*\r\n
# <- User-Agent: Ruby\r\n
# <- Connection: close\r\n
# <- Host: localhost:9292
# <- Content-Length: 4\r\n
# <- Content-Type: application/x-www-form-urlencoded\r\n\r\n"
# <- "data"
#
# -> "HTTP/1.1 200 OK\r\n"
# -> "Content-Type: text/html;charset=utf-8\r\n"
# -> "Content-Length: 0\r\n"
# -> "X-Xss-Protection: 1; mode=block\r\n"
# -> "X-Content-Type-Options: nosniff\r\n"
# -> "X-Frame-Options: SAMEORIGIN\r\n"
# -> "Server: WEBrick/1.8.1 (Ruby/3.2.0/2022-12-25)\r\n"
# -> "Date: Thu, 28 Mar 2024 17:19:21 GMT\r\n"
# -> "Connection: close\r\n"
# -> "\r\n"
# reading 0 bytes...
# -> ""
# read 0 bytes
# Conn close
# => #<Net::HTTPOK 200 OK readbody=true>
```

### To verify a valid signature:

```ruby
test_ed25519_key_pub = key.material.public_to_pem
# => "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAK1ZrC4JqC356pRsUiLVJdFZ3dAjo909VfWs1li33MCQ=\n-----END PUBLIC KEY-----\n"

pubkey = Linzer.new_ed25519_public_key(test_ed25519_key_pub, "some-key-ed25519")
# => #<Linzer::Ed25519::Key:0x00000fe19b9384b0

# if you have to, there is a helper method to build a request object on the server side
# although any standard Ruby web server or framework (Sinatra, Rails, etc) should expose
# a request object and this should not be required for most cases.
#
# request = Linzer.new_request(:post, "/some_uri", {}, headers)

message = Linzer::Message.new(request)

signature = Linzer::Signature.build(message.headers)

Linzer.verify(pubkey, message, signature)
# => true
```

To mitigate the risk of "replay attacks" (i.e. an attacker capturing a message with a valid signature and re-sending it at a later point) applications may want to validate the `created` parameter of the signature. Linzer can do this automatically when given the optional `no_older_than` keyword argument:

```ruby
Linzer.verify(pubkey, message, signature, no_older_than: 500)
```

`no_older_than` expects a number of seconds, but you can pass anything that to responds to `#to_i`, including an `ActiveSupport::Duration`.
`::verify` will raise if the `created` parameter of the signature is older than the given number of seconds.

### What if an invalid signature if verified?

```ruby
result = Linzer.verify(pubkey, message, signature)
lib/linzer/verifier.rb:38:in `verify_or_fail': Failed to verify message: Invalid signature. (Linzer::Error)
```

### HTTP responses are also supported

HTTP responses can also be signed and verified in the same way as requests.

```ruby
headers = {
  "date" => "Sat, 30 Mar 2024 21:40:13 GMT",
  "x-response-custom" => "bar"
}

response = Linzer.new_response("request body", 200, headers)
# or just use the response object exposed by your HTTP framework

message = Linzer::Message.new(response)
fields  = %w[@status date x-response-custom]

signature = Linzer.sign(key, message, fields)

pp signature.to_h
# => {"signature"=>
#   "sig1=:tCldwXqbISktyABrmbhszo...",
#  "signature-input"=>"sig1=(\"@status\" \"date\" ..."}

```

For now, to consult additional details just take a look at source code and/or the unit tests.

Please note that is still early days and extensive testing is still ongoing. For now only the following algorithms are supported: RSASSA-PSS using SHA-512, HMAC-SHA256, Ed25519 and ECDSA (P-256 and P-384 curves).

I'll be expanding the library to cover more functionality specified in the RFC
in subsequent releases.

## Ruby version compatibility

linzer is built in [Continuous Integration](https://github.com/nomadium/linzer/actions/workflows/main.yml) on Ruby 3.0+.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nomadium/linzer. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Linzer project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).
