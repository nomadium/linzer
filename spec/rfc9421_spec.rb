# frozen_string_literal: true

RSpec.describe "RFC9421" do
  def serialize(component)
    Linzer::FieldId.serialize(component)
  end

  def signature_base_lines(message, components)
    serialized_components = components.map(&method(:serialize))
    signature_base = Linzer.signature_base(message, serialized_components, {})
    signature_base.lines[0...serialized_components.length].join
  end

  context "HTTP Fields (Section 2.1)" do
    let(:uri) { URI("http://www.example.com") }

    let(:headers) do
      # Net::HTTP (and also Rack) canonicalizes component values for header fields
      # as described in https://datatracker.ietf.org/doc/html/rfc9421#section-2.1-5
      {
        "Host"              => uri.authority,
        "Date"              => "Tue, 20 Apr 2021 02:07:56 GMT",
        "X-OWS-Header"      => "   Leading and trailing whitespace.   ",
        "X-Obs-Fold-Header" => "Obsolete line folding.",
        "Cache-Control"     => "max-age=60, must-revalidate",
        "Example-Dict"      => " a=1,    b=2;x=1;y=2,   c=(a   b   c)"
      }
    end

    let(:request) { Net::HTTP::Get.new(uri, headers) }

    describe "Component values for header fields" do
      it "example 1" do
        message = Linzer::Message.new(request)
        components = %w[host date x-ows-header x-obs-fold-header cache-control example-dict]

        expect(signature_base_lines(message, components))
          .to eq(
            <<~VALUES
              "host": www.example.com
              "date": Tue, 20 Apr 2021 02:07:56 GMT
              "x-ows-header": Leading and trailing whitespace.
              "x-obs-fold-header": Obsolete line folding.
              "cache-control": max-age=60, must-revalidate
              "example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c)
            VALUES
          )
      end

      it "example 2, empty header case" do
        headers = {"X-Empty-Header" => ""}
        request = Net::HTTP::Get.new(uri, headers)
        message = Linzer::Message.new(request)
        components = %w[x-empty-header]

        expect(signature_base_lines(message, components).chomp)
          .to eq('"x-empty-header": ')
      end
    end

    describe "Strict Serialization of HTTP Structured Fields (section 2.1.1)" do
      it "example 1" do
        message = Linzer::Message.new(request)
        components = %w[example-dict]

        expect(signature_base_lines(message, components).chomp)
          .to eq('"example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c)')
      end

      it "example 2" do
        message = Linzer::Message.new(request)
        components = %w["example-dict";sf]

        expect(signature_base_lines(message, components).chomp)
          .to eq('"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)')
      end
    end

    describe "Dictionary Structured Field Members (section 2.1.2)" do
      it "example 1" do
        request["Example-Dict"] = "  a=1, b=2;x=1;y=2, c=(a   b    c), d"
        message = Linzer::Message.new(request)
        components = %w[a d b c].map { |k| "\"example-dict\";key=\"#{k}\"" }

        expect(signature_base_lines(message, components))
          .to eq(
            <<~VALUES
              "example-dict";key="a": 1
              "example-dict";key="d": ?1
              "example-dict";key="b": 2;x=1;y=2
              "example-dict";key="c": (a b c)
            VALUES
          )
      end
    end

    # The example shown in 2.1.3 with the same field but 2 distinct field values
    # would be received in Rack as one single field:
    #
    # Example-Header: value, with, lots
    # Example-Header: of, commas
    #
    # would be received by the app as:
    #
    # Example-Header: value, with, lots, of, commas

    describe "Binary-Wrapped HTTP Fields (section 2.1.3)" do
      let(:request) { Net::HTTP::Get.new(uri) }

      it "example 1" do
        request["example-header"] = "value, with, lots, of, commas"
        message = Linzer::Message.new(request)

        components = %w[example-header]
        expect(signature_base_lines(message, components).chomp)
          .to eq('"example-header": value, with, lots, of, commas')

        components = %w["example-header";bs]
        expect(signature_base_lines(message, components).chomp)
          .to eq('"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:')
      end

      it "example 2" do
        request["example-header"] = "value, with, lots"
        components = %w["example-header";bs]
        message = Linzer::Message.new(request)

        expect(signature_base_lines(message, components).chomp)
          .to eq('"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:')
      end

      it "example 3" do
        request["example-header"] = "of, commas"
        components = %w["example-header";bs]
        message = Linzer::Message.new(request)

        expect(signature_base_lines(message, components).chomp)
          .to eq('"example-header";bs: :b2YsIGNvbW1hcw==:')
      end
    end

    # unfortunately Net::HTTP doesn't support trailers
    #
    # describe "Trailer Fields (section 2.1.4)" do
    #   xit "[trailers] example 2.1.4" do
    #     headers = {
    #       "Trailer" => "Expires",
    #       "Content-Type" => "text/plain",
    #       "Transfer-Encoding" => "chunked"
    #     }
    #     body = %w[4 HTTP 7 Message a Signatures 0]
    #     expire_date = "Wed, 9 Nov 2022 07:28:00 GMT"
    #     body.define_singleton_method(:trailers) { {"expires" => expire_date} }
    #
    #     components = %w[@status trailer expires;tr]
    #     response = Net::HTTPOK.new("1.1", "200", "OK")
    #     response.body = body
    #     headers.each { |k, v| response[k] = v }
    #     response.instance_variable_set(:@read, true)
    #
    #     message = Linzer::Message.new(response)
    #
    #     expect(signature_base_lines(message, components))
    #       .to eq(
    #         <<~VALUES
    #           "@status": 200
    #           "trailer": Expires
    #           "expires";tr: Wed, 9 Nov 2022 07:28:00 GMT
    #         VALUES
    #       )
    #   end
    # end
  end

  context "Derived Components (Section 2.2)" do
    let(:request) do
      Net::HTTP::Post.new(URI("http://www.example.com/path?param=value"))
    end

    let(:message) { Linzer::Message.new(request) }

    def signature_base_line(component, message)
      Linzer::Common.signature_base_line(component, message)
    end

    describe "@method (section 2.2.1)" do
      let(:component) { "@method" }

      it "returns the HTTP method of a request message" do
        expect(signature_base_line(component, message)).to eq('"@method": POST')
        expect(message[component]).to                      eq("POST")
      end
    end

    describe "@target-uri (section 2.2.2)" do
      let(:component) { "@target-uri" }

      it "returns the target URI of a request message" do
        expected_target = "http://www.example.com/path?param=value"

        expect(signature_base_line(component, message))
          .to eq("\"@target-uri\": #{expected_target}")
        expect(message[component]).to eq(expected_target)
      end
    end

    describe "@authority (section 2.2.3)" do
      let(:component) { "@authority" }

      it "returns the authority component of the target URI of the HTTP request" do
        expected_authority = "www.example.com"

        expect(signature_base_line(component, message))
          .to eq("\"@authority\": #{expected_authority}")
        expect(message[component]).to eq(expected_authority)
      end
    end

    describe "@scheme (section 2.2.4)" do
      let(:component) { "@scheme" }

      it "returns the scheme of the target URL of the HTTP request message" do
        expect(signature_base_line(component, message)).to eq('"@scheme": http')
        expect(message[component]).to                      eq("http")
      end
    end

    describe "@request-target (section 2.2.5)" do
      let(:component) { "@request-target" }

      describe "returns the full request target of the HTTP request message" do
        it "example 1" do
          expect(signature_base_line(component, message))
            .to eq('"@request-target": /path?param=value')
          expect(message[component]).to eq("/path?param=value")
        end

        # AFAICT, Net::HTTP doesn't support how to represent requests to an HTTP
        # proxy with the absolute-form value, containing the fully qualified target
        # URI
        #
        # xit "example 2" do
        #   request = Net::HTTP::Get.new(URI("http://www.example.com/path?param=value"))
        #   expect(signature_base_line(component, message))
        #     .to eq('"@request-target": https://www.example.com/path?param=value')
        #   expect(message[component])
        #     .to eq("https://www.example.com/path?param=value")
        # end

        # Ditto for:
        # The following CONNECT request with an authority-form value, containing
        # the host and port of the target:
        #
        # CONNECT www.example.com:80 HTTP/1.1
        # Host: www.example.com
        # would result in the following @request-target component value:
        #
        # www.example.com:80
        # and the following signature base line
        # with the absolute-form value, containing the fully qualified target URI
        # "@request-target": www.example.com:80
        #
        # xit "example 3" do
        #   ...
        # end

        # And this one...
        # fails with 'Net::HTTPGenericRequest#initialize': not an HTTP URI (ArgumentError)
        #
        # xit "example 4" do
        #   request = Net::HTTP::Options.new(URI("*"))
        #   message = Linzer::Message.new(request)
        #   expect(signature_base_line(component, message))
        #     .to eq('"@request-target": *')
        #   expect(message[component]).to eq("*")
        # end
      end
    end

    describe "@path (section 2.2.6)" do
      let(:component) { "@path" }

      it "returns the target path of the HTTP request message" do
        expect(signature_base_line(component, message)).to eq('"@path": /path')
        expect(message[component]).to                      eq("/path")
      end
    end

    describe "@query (section 2.2.7)" do
      let(:component) { "@query" }

      describe "return the query component of the HTTP request message" do
        it "example 1" do
          url = "http://www.example.com/path?param=value&foo=bar&baz=bat%2Dman"
          request = Net::HTTP::Get.new(URI(url))
          message = Linzer::Message.new(request)

          expect(signature_base_line(component, message))
            .to eq('"@query": ?param=value&foo=bar&baz=bat%2Dman')
          expect(message[component]).to eq("?param=value&foo=bar&baz=bat%2Dman")
        end

        it "example 2" do
          url = "http://www.example.com/path?queryString"
          request = Net::HTTP::Post.new(URI(url))
          message = Linzer::Message.new(request)

          expect(signature_base_line(component, message))
            .to eq('"@query": ?queryString')
          expect(message[component]).to eq("?queryString")
        end

        it "example 3" do
          url = "http://www.example.com/path"
          request = Net::HTTP::Get.new(URI(url))
          message = Linzer::Message.new(request)

          expect(signature_base_line(component, message)).to eq('"@query": ?')
          expect(message[component]).to                      eq("?")
        end
      end
    end

    describe "@query-param (section 2.2.8)" do
      describe "returns the individual query parameters" do
        it "example 1" do
          url = "http://www.example.com/path?param=value&foo=bar&baz=batman&qux="
          request = Net::HTTP::Get.new(URI(url))
          message = Linzer::Message.new(request)
          components =
            %w[baz qux param].map { |p| "\"@query-param\";name=\"#{p}\"" }

          expect(signature_base_lines(message, components))
            .to eq(
              <<~VALUES
                "@query-param";name="baz": batman
                "@query-param";name="qux": 
                "@query-param";name="param": value
              VALUES
            )
          expect(message['"@query-param";name="baz"']).to   eq("batman")
          expect(message['"@query-param";name="qux"']).to   eq("")
          expect(message['"@query-param";name="param"']).to eq("value")
        end

        it "example 2" do
          url = "http://www.example.com/parameters?" \
                "var=this%20is%20a%20big%0Amultiline%20value&" \
                "bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"
          headers = {"Date" => "Tue, 20 Apr 2021 02:07:56 GMT"}
          request = Net::HTTP::Get.new(URI(url), headers)
          message = Linzer::Message.new(request)
          component_names = %w[var bar fa%C3%A7ade%22%3A%20]
          components = component_names.map { |p| "\"@query-param\";name=\"#{p}\"" }

          expect(signature_base_lines(message, components))
            .to eq(
              <<~VALUES
                "@query-param";name="var": this%20is%20a%20big%0Amultiline%20value
                "@query-param";name="bar": with%20plus%20whitespace
                "@query-param";name="fa%C3%A7ade%22%3A%20": something
              VALUES
            )
        end
      end
    end

    describe "@status (section 2.2.9)" do
      let(:response)  { Net::HTTPOK.new("1.1", "200", "OK") }
      let(:component) { "@status" }
      let(:message)   { Linzer::Message.new(response) }

      it "returns the three-digit numeric HTTP status code of a response message" do
        expect(signature_base_line(component, message)).to eq('"@status": 200')
        expect(message[component]).to                      eq(200)
      end
    end
  end

  context "Signature Parameters (Section 2.3)" do
    it "has the serialization of the signature parameters for a signature" do
      serialized_params = '("@target-uri" "@authority" "date" "cache-control")' \
                          ';keyid="test-key-rsa-pss";alg="rsa-pss-sha512";' \
                          "created=1618884475;expires=1618884775"
      signature_params = Starry.parse_list(serialized_params).shift

      parameters = signature_params.parameters
      expect(parameters["keyid"]).to   eq("test-key-rsa-pss")
      expect(parameters["alg"]).to     eq("rsa-pss-sha512")
      expect(parameters["created"]).to eq(1618884475)
      expect(parameters["expires"]).to eq(1618884775)

      components = signature_params.value.map(&:value)
      expect(components).to eq(%w[@target-uri @authority date cache-control])
    end
  end

  context "Signing Request Components in a Response Message (Section 2.4)" do
    let(:uri) { URI("http://example.com/foo?param=Value&Pet=dog") }

    let(:request) do
      headers = {
        "Host"           => "example.com",
        "Date"           => "Tue, 20 Apr 2021 02:07:55 GMT",
        "Content-Digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T" \
                            "aPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "Content-Type"   => "application/json",
        "Content-Length" => "18"
      }
      body = '{"hello": "world"}'
      request = Net::HTTP::Post.new(uri, headers)
      request.body = body
      request
    end

    let(:response_headers) do
      {
        "Date"           => "Tue, 20 Apr 2021 02:07:56 GMT",
        "Content-Type"   => "application/json",
        "Content-Length" => "62",
        "Content-Digest" => "sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwn" \
                            "HJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:"
      }
    end

    let(:response) do
      response = Net::HTTPServiceUnavailable.new("1.1", 503, "Service Unavailable")

      response.body = '{"busy": true, "message": "Your call is very important to us"}'
      response.instance_variable_set(:@read, true)

      response_headers.each { |h, v| response[h] = v }

      response
    end

    let(:test_key_ecc_p256_pub) { Linzer::RFC9421::Examples.test_key_ecc_p256_pub }
    let(:key_id) { "test-key-ecc-p256" }

    it "example signature base" do
      message = Linzer::Message.new(response, attached_request: request)
      serialized_signature_params =
        '("@status" "content-digest" "content-type" ' \
        '"@authority";req "@method";req "@path";req "content-digest";req)' \
        ';created=1618884479;keyid="test-key-ecc-p256"'

      signature_params = Starry.parse_list(serialized_signature_params).shift
      components = signature_params.value.map { |i| Starry.serialize(i) }
      parameters = signature_params.parameters

      expect(Linzer.signature_base(message, components, parameters))
        .to eq(
          <<~VALUES
            "@status": 503
            "content-digest": #{response["content-digest"]}
            "content-type": application/json
            "@authority";req: example.com
            "@method";req: POST
            "@path";req: /foo
            "content-digest";req: #{request["content-digest"]}
            "@signature-params": #{signature_params}
          VALUES
          .chomp
        )
    end

    it "example signed response" do
      signature_headers = {
        "signature-input" =>
          'reqres=("@status" "content-digest" "content-type" ' \
          '"@authority";req "@method";req "@path";req "content-digest";req)' \
          ';created=1618884479;keyid="test-key-ecc-p256"',
        "signature" => "reqres=:dMT/A/76ehrdBTD/2Xx8QuKV6FoyzEP/I9hdzKN8LQJLNgzU" \
                       "4W767HK05rx1i8meNQQgQPgQp8wq2ive3tV5Ag==:"
      }

      signature = Linzer::Signature.build(signature_headers)
      message = Linzer::Message.new(response, attached_request: request)
      pubkey = Linzer.new_ecdsa_p256_sha256_key(test_key_ecc_p256_pub)

      expect(Linzer.verify(pubkey, message, signature)).to eq(true)
    end
  end
end
