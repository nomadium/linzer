# frozen_string_literal: true

RSpec.describe Linzer::Message do
  describe "#request?" do
    it "returns true on a HTTP request message" do
      message = described_class.new(Rack::Request.new({}))
      expect(message.request?).to  eq(true)
      expect(message.response?).to eq(false)
    end
  end

  describe "#response?" do
    it "returns true on a HTTP response message" do
      message = described_class.new(Rack::Response.new)
      expect(message.response?).to eq(true)
      expect(message.request?).to  eq(false)
    end
  end

  describe "#[]" do
    it "returns the authority pseudo-header of an incoming request" do
      server = "www.example.org"
      request = Linzer.new_request(:get, "/foo", {}, {"Host" => server})
      message = described_class.new(request)
      expect(message["@authority"]).to eq(server)
    end

    it "returns the HTTP method of an incoming request" do
      request = Linzer.new_request(:put)
      message = described_class.new(request)
      expect(message["@method"]).to eq("PUT")
    end

    it "returns the full path of the request URI" do
      request = Linzer.new_request(:post, "/something")
      message = described_class.new(request)
      expect(message["@path"]).to eq("/something")
    end

    it "returns the status code of the response" do
      response = Linzer.new_response("body", 202, {})
      message = described_class.new(response)
      expect(message["@status"]).to eq(202)
    end

    it "returns the full target URI for a request" do
      server = "www.example.org"
      scheme = "http"
      path = "/target/example"
      headers = {"Host" => server}
      request = Linzer.new_request(:get, path, {}, headers)
      request.env["rack.url_scheme"] = scheme
      expected_target_uri = "#{scheme}://#{server}#{path}"
      message = described_class.new(request)
      expect(message["@target-uri"]).to eq(expected_target_uri)
    end

    it "returns the scheme of the target URI for a request" do
      scheme = "https"
      path = "/target/example2"
      request = Linzer.new_request(:get, path, {}, {})
      request.env["rack.url_scheme"] = scheme
      message = described_class.new(request)
      expect(message["@scheme"]).to eq(scheme)
    end

    it "returns the request target" do
      path = "/path"
      request = Linzer.new_request(:post, path, {}, {})
      query_string = "param=value"
      request.env["QUERY_STRING"] = query_string
      message = described_class.new(request)
      expected_target = "#{path}?#{query_string}"
      expect(message["@request-target"]).to eq(expected_target)
    end

    it "returns the query portion of the target URI for a request, example 1" do
      path = "/path"
      request = Linzer.new_request(:get, path, {}, {})
      query_string = "param=value&foo=bar&baz=bat%2Dman"
      request.env["QUERY_STRING"] = query_string
      message = described_class.new(request)
      expected_query = "?#{query_string}"
      expect(message["@query"]).to eq(expected_query)
    end

    it "returns the query portion of the target URI for a request, example 2" do
      path = "/path"
      request = Linzer.new_request(:get, path, {}, {})
      query_string = "queryString"
      request.env["QUERY_STRING"] = query_string
      message = described_class.new(request)
      expected_query = "?#{query_string}"
      expect(message["@query"]).to eq(expected_query)
    end

    it "returns the query portion of the target URI for a request, example 3" do
      path = "/path"
      request = Linzer.new_request(:get, path, {}, {})
      message = described_class.new(request)
      expected_query = "?"
      expect(message["@query"]).to eq(expected_query)
    end

    it "returns query parameter of the request target URI" do
      path = "/path"
      query_string = "param=value&foo=bar&baz=batman&qux="
      request = Linzer.new_request(:get, path, {}, {})
      request.env["QUERY_STRING"] = query_string
      message = described_class.new(request)
      expect(message["@query-param;name=\"baz\""]).to    eq("batman")
      expect(message["@query-param;name=\"qux\""]).to    eq("")
      expect(message["@query-param;name=\"param\""]).to  eq("value")
    end

    it "returns parsed and encoded query parameter of the request target URI" do
      path = "/parameters"
      query_string = "var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"
      request = Linzer.new_request(:get, path, {}, {})
      request.env["QUERY_STRING"] = query_string
      message = described_class.new(request)
      expected_var_value    = "this%20is%20a%20big%0Amultiline%20value"
      expected_bar_value    = "with%20plus%20whitespace"
      expected_facade_value = "something"
      expect(message["@query-param;name=\"var\""]).to eq(expected_var_value)
      expect(message["@query-param;name=\"bar\""]).to eq(expected_bar_value)
      expect(message["@query-param;name=\"fa%C3%A7ade%22%3A%20\""]).to eq(expected_facade_value)
    end

    it "returns null on invalid field on request" do
      request = Linzer.new_request(:put, "/bar", {}, {"x-foo" => "baz"})
      message = described_class.new(request)
      expect(message["@query-param;name=%20"]).to eq(nil)
    end

    it "returns null on not found query-param field on request" do
      request = Linzer.new_request(:get, "/", {}, {"x-not-found" => "missing"})
      message = described_class.new(request)
      expect(message['@query-param;name="not_found"']).to eq(nil)
    end

    it "returns null on undefined field on request" do
      request = Linzer.new_request(:put, "/bar", {}, {"x-foo" => "baz"})
      message = described_class.new(request)
      expect(message["x-not-in-message"]).to eq(nil)
    end

    context "HTTP component names with parameters" do
      it "returns serialized component value" do
        example_dictionary = " a=1,    b=2;x=1;y=2,   c=(a   b   c)"
        serialized_dictionary = "a=1, b=2;x=1;y=2, c=(a b c)"
        headers = {"Example-Dict" => example_dictionary, "X-Baz" => "bar"}
        request = Linzer.new_request(:put, "/bar", {}, headers)
        message = described_class.new(request)
        expect(message["x-baz"]).to           eq("bar")
        expect(message["example-dict"]).to    eq(example_dictionary.strip)
        expect(message["example-dict;sf"]).to eq(serialized_dictionary)
      end

      it "returns a single member value from a dictionary structured field" do
        example_dictionary = " a=1, b=2;x=1;y=2, c=(a   b    c), d"
        headers = {"Example-Dict" => example_dictionary, "X-Foo" => "ok"}
        request = Linzer.new_request(:post, "/foo", {}, headers)
        message = described_class.new(request)
        expect(message["x-foo"]).to eq("ok")
        expect(message['example-dict;key="a"']).to eq("1")
        expect(message['example-dict;key="d"']).to eq("?1")
        expect(message['example-dict;key="b"']).to eq("2;x=1;y=2")
        expect(message['example-dict;key="c"']).to eq("(a b c)")
      end

      it "returns field values encoded using byte sequence data structures" do
        value_with_commas = "value, with, lots, of, commas"
        encoded_value = ":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:"
        headers = {"Example-Header" => value_with_commas}
        request = Linzer.new_request(:get, "/something", {}, headers)
        message = described_class.new(request)
        expect(message["example-header;bs"]).to eq(encoded_value)
      end

      it "returns field value is from the trailers" do
        headers = {"Trailer" => "Expires"}
        body = ["Hello", "World"]
        expire_date = "Wed, 9 Nov 2022 07:28:00 GMT"
        def body.trailers
          {"expires" => "Wed, 9 Nov 2022 07:28:00 GMT"}
        end
        response = Linzer.new_response(body, 200, headers)
        message = described_class.new(response)
        expect(message["@status"]).to    eq(200)
        expect(message["trailer"]).to    eq("Expires")
        expect(message["expires;tr"]).to eq(expire_date)
      end

      it "returns null on invalid field name" do
        request = Linzer.new_request(:get, "/", {}, {})
        message = described_class.new(request)
        expect(message["%20"]).to eq(nil)
      end

      it "returns component value derived from the request" do
        req_content_digest = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        req_headers = {
          "Host" => "example.com",
          "Date" => "Tue, 20 Apr 2021 02:07:55 GMT",
          "Content-Digest" => req_content_digest,
          "Content-Type" => "application/json",
          "Content-Length" => 18
        }
        request = Linzer.new_request(:post, "/foo", {}, req_headers)
        query_string = "param=Value&Pet=dog"
        request.env["QUERY_STRING"] = query_string

        resp_headers = {
          "Date"           => "Tue, 20 Apr 2021 02:07:56 GMT",
          "Content-Type"   => "application/json",
          "Content-Length" => 62,
          "Content-Digest" => "sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:"
        }
        body = '{"busy": true, "message": "Your call is very important to us"}'
        response = Linzer.new_response(body, 503, resp_headers)

        message = described_class.new(response, attached_request: request)
        expect(message["@authority;req"]).to     eq("example.com")
        expect(message["@method;req"]).to        eq("POST")
        expect(message["@path;req"]).to          eq("/foo")
        expect(message["content-digest;req"]).to eq(req_content_digest)
      end
    end
  end

  describe "#field?" do
    it "returns true if the requested field is defined on the message" do
      response = Linzer.new_response(nil, 301, {})
      message = described_class.new(response)
      expect(message.field?("@status")).to eq(true)
      expect(message["@status"]).to        be_truthy
    end

    it "returns false if the requested field is not defined on the message" do
      request = Linzer.new_request(:get, "/baz", {}, {"content-type" => "application/json"})
      message = described_class.new(request)
      expect(message.field?("x-missing")).to eq(false)
      expect(message["x-missing"]).to        be_falsey
    end
  end

  describe "#headers" do
    let(:headers) { {"content-type" => "application/json", "foo" => "bar"} }

    it "returns HTTP headers from message request" do
      request = Linzer.new_request(:options, "/foo", {}, headers)
      message = described_class.new(request)
      expect(message.request?).to eq(true)
      expect(message.headers).to  eq(headers)
    end

    it "returns HTTP headers from message response" do
      response = Linzer.new_response("body", 302, headers)
      message = described_class.new(response)
      expect(message.response?).to eq(true)
      expect(message.headers).to   eq(headers)
    end
  end

  describe "::parse_structured_dictionary" do
    it "parses HTTP structured dictionaries" do
      dict = 'sig-b26=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"'
      parsed_dict = described_class.parse_structured_dictionary(dict)

      expect(parsed_dict["sig-b26"].to_a.map(&:value))
        .to eq(%w[@status content-type content-digest content-length])
    end

    it "raises an error on unparsable strings" do
      expect { described_class.parse_structured_dictionary('puts "hello world"') }
        .to raise_error(Linzer::Error, /Cannot parse/)
    end
  end
end
