# frozen_string_literal: true

RSpec.describe "RFC9421" do
  context "Section 2.1" do
    let(:uri) { URI("http://www.example.com") }

    let(:env_fields) do
      # Rack seems to canonicalize component values for header fields as described
      # https://datatracker.ietf.org/doc/html/rfc9421#section-2.1-5
      {
        "HTTP_HOST"              => uri.authority,
        "HTTP_DATE"              => "Tue, 20 Apr 2021 02:07:56 GMT",
        "HTTP_X_OWS_HEADER"      => "Leading and trailing whitespace.",
        "HTTP_X_OBS_FOLD_HEADER" => "Obsolete line folding.",
        "HTTP_CACHE_CONTROL"     => "max-age=60, must-revalidate",
        "HTTP_EXAMPLE_DICT"      => "a=1,    b=2;x=1;y=2,   c=(a   b   c)"
      }
    end

    it "returns the expected component values using signature base format" do
      request = Rack::Request.new(Rack::MockRequest.env_for(uri, **env_fields))
      message = Linzer::Message.new(request)
      components = %w[host date x-ows-header x-obs-fold-header cache-control example-dict]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join)
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

    it "returns the expected component values using signature base format, empty header" do
      uri = URI("http://www.example.com")
      env_fields = {"HTTP_X_EMPTY_HEADER" => ""}
      request = Rack::Request.new(Rack::MockRequest.env_for(uri, **env_fields))
      message = Linzer::Message.new(request)
      components = %w[x-empty-header]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join.chomp).to eq('"x-empty-header": ')
    end

    it "section 2.1.1, example 1" do # XXX: rename?
      uri = URI("http://www.example.com")
      request = Rack::Request.new(Rack::MockRequest.env_for(uri, **env_fields))
      message = Linzer::Message.new(request)
      components = %w[example-dict]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join.chomp)
        .to eq('"example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c)')
    end

    it "section 2.1.1, example 2" do # XXX: rename?
      uri = URI("http://www.example.com")
      request = Rack::Request.new(Rack::MockRequest.env_for(uri, **env_fields))
      message = Linzer::Message.new(request)
      components = %w[example-dict;sf]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join.chomp)
        .to eq('"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)')
    end

    it "returns the expected component values using signature base format, example 2.1.2" do
      uri = URI("http://www.example.com")
      env_fields = {"HTTP_EXAMPLE_DICT" => "  a=1, b=2;x=1;y=2, c=(a   b    c), d"}

      request = Rack::Request.new(Rack::MockRequest.env_for(uri, **env_fields))
      message = Linzer::Message.new(request)
      components = %w[a d b c].map { |k| "example-dict;key=\"#{k}\"" }
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join)
        .to eq(
          <<~VALUES
            "example-dict";key="a": 1
            "example-dict";key="d": ?1
            "example-dict";key="b": 2;x=1;y=2
            "example-dict";key="c": (a b c)
          VALUES
        )
    end

    # The example shown in 2.1.3 with the same header but 2 different values
    # would be representable in rack as one single header:
    #
    # Example-Header: value, with, lots
    # Example-Header: of, commas
    #
    # would be received by the app as:
    #
    # Example-Header: value, with, lots, of, commas

    it "returns the expected component values using signature base format, example 2.1.3" do
      uri = URI("http://www.example.com")
      env_fields = {
        "HTTP_EXAMPLE_HEADER"  => "value, with, lots, of, commas",
        "HTTP_EXAMPLE_HEADER2" => "value, with, lots",
        "HTTP_EXAMPLE_HEADER3" => "of, commas"
      }

      request = Rack::Request.new(Rack::MockRequest.env_for(uri, **env_fields))
      message = Linzer::Message.new(request)
      components = %w[example-header]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join.chomp)
        .to eq('"example-header": value, with, lots, of, commas')

      components = %w[example-header;bs]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join.chomp)
        .to eq('"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:')

      components = %w[example-header2;bs]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join.chomp)
        .to eq('"example-header2";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:')

      components = %w[example-header3;bs]
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join.chomp)
        .to eq('"example-header3";bs: :b2YsIGNvbW1hcw==:')
    end

    it "[trailers] example 2.1.4" do
      headers = {
        "Trailer" => "Expires",
        "Content-Type" => "text/plain",
        "Transfer-Encoding" => "chunked"
      }
      body = %w[4 HTTP 7 Message a Signatures 0]
      expire_date = "Wed, 9 Nov 2022 07:28:00 GMT"
      body.define_singleton_method(:trailers) { {"expires" => expire_date} }

      components = %w[@status trailer expires;tr]
      response = Linzer::Test::RackHelper.new_response(body, 200, headers)
      message = Linzer::Message.new(response)
      signature_base = Linzer.signature_base(message, components, {})

      expect(signature_base.lines[0...components.length].join)
        .to eq(
          <<~VALUES
            "@status": 200
            "trailer": Expires
            "expires";tr: Wed, 9 Nov 2022 07:28:00 GMT
          VALUES
        )
    end
  end

  context "Section 2.2" do
    let(:request) do
      Net::HTTP::Post.new(URI("http://www.example.com/path?param=value"))
    end

    let(:message) { Linzer::Message.new(request) }

    def signature_base_line(message, component)
      signature_base = Linzer.signature_base(message, [component], {})
      signature_base.lines[0...[component].length].join.chomp
    end

    describe "@method (section 2.2.1)" do
      let(:component) { "@method" }

      it "returns the HTTP method of a request message" do
        expect(signature_base_line(message, component)).to eq('"@method": POST')
        expect(message[component]).to                      eq("POST")
      end
    end

    describe "@target-uri (section 2.2.2)" do
      let(:component) { "@target-uri" }

      it "returns the target URI of a request message" do
        expected_target = "http://www.example.com/path?param=value"

        expect(signature_base_line(message, component))
          .to eq("\"@target-uri\": #{expected_target}")
        expect(message[component]).to eq(expected_target)
      end
    end

    describe "@authority (section 2.2.3)" do
      let(:component) { "@authority" }

      it "returns the authority component of the target URI of the HTTP request" do
        expected_authority = "www.example.com"

        expect(signature_base_line(message, component))
          .to eq("\"@authority\": #{expected_authority}")
        expect(message[component]).to eq(expected_authority)
      end
    end

    describe "@scheme (section 2.2.4)" do
      let(:component) { "@scheme" }

      it "returns the scheme of the target URL of the HTTP request message" do
        expect(signature_base_line(message, component)).to eq('"@scheme": http')
        expect(message[component]).to                      eq("http")
      end
    end

    describe "@request-target (section 2.2.5)" do
      let(:component) { "@request-target" }

      describe "returns the full request target of the HTTP request message" do
        it "example 1" do
          expect(signature_base_line(message, component))
            .to eq('"@request-target": /path?param=value')
          expect(message[component]).to eq("/path?param=value")
        end

        # AFAICT, Net::HTTP doesn't support how to represent requests to an HTTP
        # proxy with the absolute-form value, containing the fully qualified target
        # URI
        #
        # xit "example 2" do
        #   request = Net::HTTP::Get.new(URI("http://www.example.com/path?param=value"))
        #   expect(signature_base_line(component))
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
        #   expect(signature_base_line(message, component))
        #     .to eq('"@request-target": *')
        #   expect(message[component]).to eq("*")
        # end
      end
    end

    describe "@path (section 2.2.6)" do
      let(:component) { "@path" }

      it "returns the target path of the HTTP request message" do
        expect(signature_base_line(message, component)).to eq('"@path": /path')
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

          expect(signature_base_line(message, component))
            .to eq('"@query": ?param=value&foo=bar&baz=bat%2Dman')
          expect(message[component]).to eq("?param=value&foo=bar&baz=bat%2Dman")
        end

        it "example 2" do
          url = "http://www.example.com/path?queryString"
          request = Net::HTTP::Post.new(URI(url))
          message = Linzer::Message.new(request)

          expect(signature_base_line(message, component))
            .to eq('"@query": ?queryString')
          expect(message[component]).to eq("?queryString")
        end

        it "example 3" do
          url = "http://www.example.com/path"
          request = Net::HTTP::Get.new(URI(url))
          message = Linzer::Message.new(request)

          expect(signature_base_line(message, component)).to eq('"@query": ?')
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
          components = %w[baz qux param].map { |p| "@query-param;name=\"#{p}\"" }
          signature_base = Linzer.signature_base(message, components, {})

          expect(signature_base.lines[0...components.length].join)
            .to eq(
              <<~VALUES
                "@query-param";name="baz": batman
                "@query-param";name="qux": 
                "@query-param";name="param": value
              VALUES
            )
          expect(message['@query-param;name="baz"']).to   eq("batman")
          expect(message['@query-param;name="qux"']).to   eq("")
          expect(message['@query-param;name="param"']).to eq("value")
        end

        it "example 2" do
          url = "http://www.example.com/parameters?" \
                "var=this%20is%20a%20big%0Amultiline%20value&" \
                "bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something"
          headers = {"Date" => "Tue, 20 Apr 2021 02:07:56 GMT"}
          request = Net::HTTP::Get.new(URI(url), headers)
          message = Linzer::Message.new(request)
          component_names = %w[var bar fa%C3%A7ade%22%3A%20]
          components = component_names.map { |p| "@query-param;name=\"#{p}\"" }
          signature_base = Linzer.signature_base(message, components, {})

          expect(signature_base.lines[0...components.length].join)
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
        expect(signature_base_line(message, component)).to eq('"@status": 200')
        expect(message[component]).to                      eq(200)
      end
    end
  end
end
