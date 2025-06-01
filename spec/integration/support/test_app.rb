require "sinatra"
require "starry"
require "digest"
require "json"
require "base64"
require "ed25519"

module Linzer
  module Test
    class TestApp < Sinatra::Base
      configure do
        set :app_key, ::Ed25519::SigningKey.generate
      end

      after do
        set_content_digest!
        sign!
      end

      get "/" do
        "Hello, world!\n"
      end

      get "/.well-known/http-message-signatures-directory" do
        now = Time.now.utc.to_i

        content_type "application/http-message-signatures-directory"

        key_params = {nbf: (now - 500) * 1000, exp: (now + 3600) * 1000}
        jwk = JWT::JWK.new(settings.app_key.verify_key, key_params)
        # https://datatracker.ietf.org/doc/html/rfc7517#section-4
        directory = {"keys" => [jwk.export], "purpose" => "rag"}
        directory.to_json
      end

      helpers do
        def set_content_digest!
          response["content-digest"] = content_digest(response.body.join)
        end

        def content_digest(data)
          Starry.serialize("sha-256" => Digest::SHA256.digest(data))
        end

        def sign!
          Linzer.sign!(
            response,
            key:        nil, # fix this, it needs a JWT key
            components: %w[@status content-digest],
            label: "sig1",
            params: {
              created: Time.now.to_i,
              keyid: settings.app_key.export[:kid]
            }
          )
        end
      end
    end
  end
end
