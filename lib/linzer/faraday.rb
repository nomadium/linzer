# frozen_string_literal: true

# Faraday integration for Linzer.
#
# Require this file to automatically register Faraday message adapters
# and the HTTP signature (RFC 9421) middleware.
#
# This sets up:
# - {Linzer::Message::Adapter::Faraday::Request} for {::Faraday::Request}
# - {Linzer::Message::Adapter::Faraday::Response} for {::Faraday::Response}
# - {Faraday::HttpSignature::Middleware} registered as +:http_signature+
#   on +Faraday::Request+, +Faraday::Response+ and +Faraday::Middleware+
#
# @example
#   require "linzer/faraday"
#
#   conn = Faraday.new(url: "https://example.com") do |f|
#     f.request :http_signature, key: my_key, components: %w[@method @path]
#   end

require "faraday"
require "linzer"
require "faraday/http_signature"
require "linzer/message/adapter/faraday/request"
require "linzer/message/adapter/faraday/response"
require "linzer/faraday/utils"

Linzer::Message.register_adapter(Faraday::Request,  Linzer::Message::Adapter::Faraday::Request)
Linzer::Message.register_adapter(Faraday::Response, Linzer::Message::Adapter::Faraday::Response)
