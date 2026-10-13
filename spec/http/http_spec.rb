# frozen_string_literal: true

RSpec.describe Linzer::HTTP do
  let(:http)         { Linzer::HTTP }
  let(:uri)          { "https://www.example.com/api/service" }
  let(:headers)      { {"date" => Time.now.utc.to_s} }
  let(:webdav_verbs) { %w[COPY LOCK MKCOL MOVE PROPFIND PROPPATCH UNLOCK] }

  # QUERY (draft-ietf-httpbis-safe-method-w-body) is only known to
  # net-http >= 0.10.0, older releases do not define Net::HTTP::Query.
  let(:query_supported) { defined?(Net::HTTP::Query) ? true : false }

  let(:http_verbs) do
    verbs = %w[DELETE GET HEAD OPTIONS PATCH POST PUT TRACE]
    verbs << "QUERY" if query_supported
    verbs
  end

  describe "::known_http_methods" do
    it "returns a list of known (by Net::HTTP module) HTTP methods/verbs" do
      known_http_verbs = (http_verbs + webdav_verbs).sort
      expect(http.known_http_methods.sort).to eq(known_http_verbs)
    end
  end

  it "has a method for every known HTTP request verb" do
    http.known_http_methods.each do |m|
      expect(http).to respond_to(m.downcase.to_sym)
    end
  end

  it "does not define a QUERY method when net-http does not support it" do
    skip "net-http #{Net::HTTP::VERSION} supports QUERY" if query_supported
    expect(http).not_to respond_to(:query)
  end

  it "raises error on unsupported or unknown HTTP request verb" do
    expect { http.send(:request, :connect, "www.example.com:443") }
      .to raise_error(Linzer::Error, /unsupported HTTP method/)
  end

  describe "::get" do
    it "sends a signed GET request" do
      net_http = instance_double("Net::HTTP")
      allow(Net::HTTP).to receive(:new).and_return(net_http)

      uri = "https://www.example.com/api/service"

      expect(net_http).to receive(:use_ssl=).with(true)
      expect(net_http).to receive(:get).with(
        uri,
        satisfy do |hsh|
          hsh.key?("signature") && hsh.key?("signature-input") && hsh.key?("date")
        end
      )

      http.get(uri, key: Linzer.generate_ed25519_key, headers: headers)
    end
  end

  describe "::post" do
    it "sends a signed POST request" do
      net_http = instance_double("Net::HTTP")
      allow(Net::HTTP).to receive(:new).and_return(net_http)

      data = "body"

      expect(net_http).to receive(:use_ssl=).with(true)
      expect(net_http).to receive(:post).with(
        uri,
        data,
        satisfy do |hsh|
          hsh.key?("signature") && hsh.key?("signature-input") && hsh.key?("date")
        end
      )

      http.post(uri,
        data:    data,
        key:     Linzer.generate_ed25519_key,
        headers: headers)
    end

    it "raises error if no request body is provided" do
      expect do
        http.post(uri,
          key: Linzer.generate_ed25519_key,
          headers: headers)
      end.to raise_error(Linzer::Error, /Missing request body/)
    end
  end

  describe "::lock" do
    it "sends a signed LOCK request" do
      net_http = instance_double("Net::HTTP")
      allow(Net::HTTP).to receive(:new).and_return(net_http)

      expect(net_http).to receive(:use_ssl=).with(true)
      expect(net_http).to receive(:lock).with(
        uri,
        "some data",
        satisfy do |hsh|
          hsh.key?("signature") && hsh.key?("signature-input") && hsh.key?("date")
        end
      )

      http.lock(uri,
        data:    "some data",
        key:     Linzer.generate_ed25519_key,
        headers: headers)
    end
  end

  describe "::query" do
    before do
      skip "net-http #{Net::HTTP::VERSION} does not support QUERY" unless query_supported
    end

    it "sends a signed QUERY request" do
      net_http = instance_double("Net::HTTP")
      allow(Net::HTTP).to receive(:new).and_return(net_http)

      data = '{"filter": "name eq \"linzer\""}'

      expect(net_http).to receive(:use_ssl=).with(true)
      expect(net_http).to receive(:query).with(
        uri,
        data,
        satisfy do |hsh|
          hsh.key?("signature") && hsh.key?("signature-input") && hsh.key?("date")
        end
      )

      http.query(uri,
        data:    data,
        key:     Linzer.generate_ed25519_key,
        headers: headers)
    end

    it "raises error if no request body is provided" do
      expect do
        http.query(uri,
          key: Linzer.generate_ed25519_key,
          headers: headers)
      end.to raise_error(Linzer::Error, /Missing request body/)
    end
  end
end
