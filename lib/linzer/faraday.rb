# frozen_string_literal: true

# Faraday integration for Linzer. Require this file to automatically
# register Faraday request/response adapters and the HTTP signature
# (RFC9421) middleware.

require "faraday"
require "linzer"
require "faraday/http_signature"
require "linzer/message/adapter/faraday/request"
require "linzer/message/adapter/faraday/response"
require "linzer/faraday/utils"

Linzer::Message.register_adapter(Faraday::Request,  Linzer::Message::Adapter::Faraday::Request)
Linzer::Message.register_adapter(Faraday::Response, Linzer::Message::Adapter::Faraday::Response)
