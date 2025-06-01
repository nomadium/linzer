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

### TL;DR: I just want to protect my application!!

Add the following middleware to your Rack application and configure it
as needed, e.g.:

```ruby
# config.ru
use Rack::Auth::Signature, except: "/login",
  default_key: {material: Base64.strict_decode64(ENV["MYAPP_KEY"]), alg: "hmac-sha256"}
  # or: default_key: {material: IO.read("app/config/pubkey.pem"), "ed25519"}
```

or on more complex scenarios:

```ruby
# config.ru
use Rack::Auth::Signature, except: "/login",
  config_path: "app/configuration/http-signatures.yml"
```

or with a typical Rails application:

```ruby
# config/application.rb
config.middleware.use Rack::Auth::Signature, except: "/login",
  config_path: "http-signatures.yml"
```

And that's it, all routes in the example app (except `/login`) above will
require a valid signature created with the respective private key held by a
client. For more details on what configuration options are available, take a
look at
[examples/sinatra/http-signatures.yml](https://github.com/nomadium/linzer/tree/master/examples/sinatra/http-signatures.yml) to get started and/or
[lib/rack/auth/signature.rb](https://github.com/nomadium/linzer/tree/master/lib/rack/auth/signature.rb) for full implementation details.

To learn about more specific scenarios or use cases, keep reading on below.

### To sign a HTTP request:

There are several options:

#### If you are using http gem:

```ruby
# first require http signatures feature class ready to be used with http gem:
require "linzer/http/signature_feature"

key = Linzer.generate_ed25519_key # generate a new key pair
# => #<Linzer::Ed25519::Key:0x00000fe13e9bd208
# or load an existing key with:
# key = Linzer.new_ed25519_key(IO.read("key"), "mykeyid")

# then send the request:
url = "https://example.org/api"
response = HTTP.headers(date: Time.now.to_s, foo: "bar")
               .use(http_signature: {key: key} # <--- covered components
               .get(url) # and signature params can also be customized on the client
=> #<HTTP::Response/1.1 200 OK {"Content-Type" => ...
response.body.to_s
=> "protected content..."
```

#### If you are using plain old Net::HTTP:

```ruby
key = Linzer.generate_ed25519_key
# => #<Linzer::Ed25519::Key:0x00000fe13e9bd208

uri = URI("https://example.org/api/task")
request = Net::HTTP::Get.new(uri)
request["date"] = Time.now.to_s

Linzer.sign!(
  request,
  key: key,
  components: %w[@method @request-target date],
  label: "sig1",
  params: {
    created: Time.now.to_i
  }
)

request["signature"]
# => "sig1=:Cv1TUCxUpX+5SVa7pH0Xh..."
request["signature-input"]
# => "sig1=(\"@method\" \"@request-target\" \"date\" ..."}
```

Then you can submit the signed request with Net::HTTP client:

```ruby
require "net/http"

http = Net::HTTP.new(uri.host, uri.port)
http.set_debug_output($stderr)
response = http.request(request)
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

#### Or you can also use the simple HTTP client bundled with this library:

(This client is probably not suitable for production use but could be useful
enough to get started. It's build on top of Net::HTTP.)

```ruby
key = Linzer.generate_rsa_pss_sha512_key(4096)
uri = URI("https://example.org/api/task")
headers = {"date" => Time.now.to_s}
response =
  Linzer::HTTP
    .post("http://httpbin.org/headers",
          data: "foo",
          debug: true,
          key: key,
          headers: headers)
...
=> #<Net::HTTPOK 200 OK readbody=true>
```

### To verify an incoming request on the server side:

The middleware `Rack::Auth::Signature` can be used for this scenario
[as shown above](#tldr-i-just-want-to-protect-my-application).

Or directly in the application controller (or routes), the incoming request can
be verified with the following approach:

```ruby
post "/foo" do
  request
  # =>
  # #<Sinatra::Request:0x000000011e5a5d60
  #  @env=
  #   {"GATEWAY_INTERFACE" => "CGI/1.1",
  #   "PATH_INFO" => "/api",
  # ...

  result = Linzer.verify!(request, key: some_client_key)
  # => true
  ...
end
```

If the signature is missing or invalid, the verification method will raise an
exception with a message clarifying why the request signature failed verification.

Also, for additional flexibility on the server side, the method above can take
a block with the `keyid` parameter extracted from the signature (if any) as argument.
This can be useful to retrieve key data from databases/caches on the server side, e.g.:

```ruby
get "/bar" do
  ...
  result = Linzer.verify!(request) do |keyid|
    retrieve_pubkey_from_db(db_client, keyid)
  end
  # => true
  ...
end
```

### To verify a received response on the client side:

It's similar to verifying requests, the same method is used, see example below:

```ruby
response
# => #<Net::HTTPOK 200 OK readbody=true>
response.body
# => "protected"
pubkey = Linzer.new_ed25519_key(IO.read("pubkey.pem"))
result = Linzer.verify!(response, key: pubkey, no_older_than: 600)
# => true
```

### To sign an outgoing response on the server side:

Again, the same principle used to sign outgoing requests, the same method is used,
see example below:

```ruby
put "/baz" do
  ...
  response
  # => #<Sinatra::Response:0x0000000109ac40b8 ...
  response.headers["x-custom-app-header"] = "..."
  Linzer.sign!(response,
    key: my_key,
    components: %w[@status content-type content-digest x-custom-app-header],
    label: "sig1",
    params: {
      created: Time.now.to_i
    }
  )
  response["signature"]
  # => "sig1=:2TPCzD4l48bg6LMcVXdV9u..."
  response["signature-input"]
  # => "sig1=(\"@status\" \"content-type\" \"content-digest\"..."
  ...
end
```

### What do you do if you want to sign/verify requests and responses with your preferred HTTP ruby library/framework (not using Rack or `Net::HTTP`, for example)?

You can provide an adapter class and then register it with this library.
For guidance on how to implement such adapters, you can consult an
[example adapter for http gem response](https://github.com/nomadium/linzer/blob/master/lib/linzer/message/adapter/http_gem/response.rb)
included with this gem or the ones
[provided out of the box](https://github.com/nomadium/linzer/blob/master/lib/linzer/message/adapter).

For how to register a custom adapter and how to verify signatures in a response,
see this example:

```ruby
Linzer::Message.register_adapter(HTTP::Response, Linzer::Message::Adapter::HTTPGem::Response)
# Linzer::Message.register_adapter(HTTP::Response, MyOwnResponseAdapter) # or use your own adapter
response = HTTP.get("http://www.example.com/api/service/task")
# => #<HTTP::Response/1.1 200 OK ...
response["signature"]
=> "sig1=:oqzDlQmfejfT..."
response["signature-input"]
=> "sig1=(\"@status\" \"foo\");created=1746480237"
result = Linzer.verify!(response, key: my_key)
# => true
```
---

Furthermore, on some low-level scenarios where a user wants or needs additional
control on how the signing and verification routines are performed, Linzer allows
to manipulate instances of internal HTTP messages (requests & responses, see
`Linzer::Message` class and available adapters), signature objects
(`Linzer::Signature`) and how to register additional message adapters for any
HTTP ruby library not supported out of the box by this gem.

See below for a few examples of these scenarios.

#### To verify a valid signature:

```ruby
test_ed25519_key_pub = key.material.public_to_pem
# => "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAK1ZrC4JqC356pRsUiLVJdFZ3dAjo909VfWs1li33MCQ=\n-----END PUBLIC KEY-----\n"

pubkey = Linzer.new_ed25519_public_key(test_ed25519_key_pub, "some-key-ed25519")
# => #<Linzer::Ed25519::Key:0x00000fe19b9384b0

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

#### What if an invalid signature if verified?

```ruby
result = Linzer.verify(pubkey, message, signature)
lib/linzer/verifier.rb:38:in `verify_or_fail': Failed to verify message: Invalid signature. (Linzer::Error)
```

#### HTTP responses are also supported

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

Please note that is still early days and extensive testing is still ongoing. For now the following algorithms are supported: RSASSA-PSS using SHA-512, RSASSA-PKCS1-v1_5 using SHA-256, HMAC-SHA256, Ed25519 and ECDSA (P-256 and P-384 curves). JSON Web Signature (JWS) algorithms mentioned in the RFC are not supported yet.

I'll be expanding the library to cover more functionality specified in the RFC
in subsequent releases.

## Ruby version compatibility

linzer is built in [Continuous Integration](https://github.com/nomadium/linzer/actions/workflows/main.yml) on Ruby 3.0+.

## Security

This gem is provided “as is” without any warranties. It has not been audited for security vulnerabilities. Users are advised to review the code and assess its suitability for their use case, particularly in production environments.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nomadium/linzer. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Linzer project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/nomadium/linzer/blob/master/CODE_OF_CONDUCT.md).
