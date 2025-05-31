require "sinatra"
require "starry"
require "digest"
require "json"
require "base64"

module Linzer
  module Test
    class TestApp < Sinatra::Base
      configure do
        set :app_key, Linzer.generate_ed25519_key
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

        # https://datatracker.ietf.org/doc/html/rfc7517#section-4
        keys = {
          "keys" => [
            {
              "kid" => kid,
              "kty" => "OKP",
              "crv" => "Ed25519",
              "x"   => Base64.urlsafe_encode64(app_raw_pubkey, padding: false),
              "nbf" => (now - 500) * 1000,
              "exp" => (now + 3600) * 1000
            }
          ],
          "purpose" => "rag"
        }

        keys.to_json
      end

      helpers do
        def set_content_digest!
          response["content-digest"] = content_digest(response.body.join)
        end

        def content_digest(data)
          Starry.serialize("sha-256" => Digest::SHA256.digest(data))
        end

        def app_raw_pubkey
          settings.app_key.material.raw_public_key
        end

        def kid
          Base64.urlsafe_encode64(Digest::SHA256.digest(app_raw_pubkey))
        end

        def sign!
          Linzer.sign!(
            response,
            key:        settings.app_key,
            components: %w[@status content-digest],
            label: "sig1",
            params: {
              created: Time.now.to_i,
              keyid: kid
            }
          )
        end
      end
    end
  end
end
