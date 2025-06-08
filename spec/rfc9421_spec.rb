# frozen_string_literal: true

RSpec.describe "RFC9421" do
  context "Section 2.1" do
    it "returns the expected component values using signature base format" do
      uri = URI("http://www.example.com")
      # Rack seems to canonicalize component values for header fields as described in
      # https://datatracker.ietf.org/doc/html/rfc9421#section-2.1-5
      env_fields = {
        "HTTP_HOST"              => uri.authority,
        "HTTP_DATE"              => "Tue, 20 Apr 2021 02:07:56 GMT",
        "HTTP_X_OWS_HEADER"      => "Leading and trailing whitespace.",
        "HTTP_X_OBS_FOLD_HEADER" => "Obsolete line folding.",
        "HTTP_CACHE_CONTROL"     => "max-age=60, must-revalidate",
        "HTTP_EXAMPLE_DICT"      => "a=1,    b=2;x=1;y=2,   c=(a   b   c)"
      }
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
  end
end
