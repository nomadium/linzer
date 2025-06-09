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

    xit "[trailers] example 2.1.4" do
    end
  end
end
