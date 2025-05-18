# frozen_string_literal: true

RSpec.describe Linzer::HTTP do
  let(:http)         { Linzer::HTTP }
  let(:uri)          { "https://www.example.com/api/service" }
  let(:headers)      { {"date" => Time.now.utc.to_s} }
  let(:http_verbs)   { %w[DELETE GET HEAD OPTIONS PATCH POST PUT TRACE]   }
  let(:webdav_verbs) { %w[COPY LOCK MKCOL MOVE PROPFIND PROPPATCH UNLOCK] }

  describe "::known_http_methods" do
    it "returns a list of known (by Net::HTTP module) HTTP methods/verbs" do
      known_http_verbs = (http_verbs + webdav_verbs).sort
      expect(http.known_http_methods.sort).to eq(known_http_verbs)
    end
  end

  it "has a method for every known HTTP request verb" do
    http.known_http_methods.each do |m|
      expect(http.respond_to?(m.downcase.to_sym))
    end
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
end
