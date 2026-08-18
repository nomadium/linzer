# frozen_string_literal: true

module Linzer
  module Test
    # Shared low-level HTTP helpers for the Web Bot Auth integration specs
    # (cloudflare_example_research_spec.rb, web_bot_auth_vercel_interop_spec.rb).
    #
    # Meant to be `include`d into an RSpec example group that also defines
    # `debug` and `headers` lets, both helpers read them from the
    # including group, the same way any other `let` is used from an `it`.
    module HTTPClients
      def net_http_client(uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.set_debug_output($stderr) if debug
        http
      end

      # `params` overrides/adds to the default recommended Web Bot Auth
      # params (created, expires, tag, keyid, nonce) applied by the
      # :web_bot_auth profile, used to craft otherwise-valid requests
      # with a deliberately broken @signature-params value.
      def linzer_http_get(uri, key, params = {})
        Linzer::HTTP.get(uri,
          key:    key,
          debug:  debug,
          covered_components: %w[@authority signature-agent],
          headers:            headers,
          profile:            :web_bot_auth,
          params:             params)
      end

      # Lower-level than linzer_http_get: needed whenever a test has to vary
      # `headers`, `components`, or `profile` themselves (a missing header, an
      # uncovered component, a profile with nonce generation disabled) rather
      # than just the signature params linzer_http_get already exposes. Yields
      # the signed-but-unsent request so callers can also mutate it further
      # (e.g. to tamper with the signature after Linzer signs it).
      def sign_and_get(key, headers: self.headers, components: %w[@authority signature-agent], profile: :web_bot_auth, params: {alg: "ed25519"})
        request = Net::HTTP::Get.new(uri, headers)

        Linzer.sign!(
          request,
          key:        key,
          profile:    profile,
          components: components,
          params:     params
        )

        yield request if block_given?

        net_http_client(uri).request(request)
      end
    end
  end
end
