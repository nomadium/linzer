# frozen_string_literal: true

RSpec.describe "Linzer::Faraday::Utils" do
  before(:all) do
    require "linzer/faraday"
  end

  let(:utils) { Linzer::Faraday::Utils }

  describe "::create_request" do
    it "returns a Faraday::Request" do
      env = Faraday::Env.new

      url = URI("https://www.google.com/")
      headers = {"X-Some-Header" => "foo", "User-Agent" => "bar"}
      http_method = :post

      env.method          = http_method
      env.url             = url
      env.request_headers = headers

      request = utils.create_request(env)

      expect(request.http_method).to eq(http_method)
      expect(request.path).to        eq(url)
      expect(request.headers).to     eq(headers)
    end

    it "preserves the request options from the environment" do
      env = Faraday::Env.new
      env.method  = :get
      env.url     = URI("https://www.example.com/")
      env.request = Faraday::RequestOptions.from(params_encoder: Faraday::FlatParamsEncoder)

      request = utils.create_request(env)

      expect(request.options.params_encoder).to eq(Faraday::FlatParamsEncoder)
    end

    it "falls back to default request options when the environment has none" do
      env = Faraday::Env.new
      env.method = :get
      env.url    = URI("https://www.example.com/")

      request = utils.create_request(env)

      expect(request.options).to be_a(Faraday::RequestOptions)
    end
  end
end
