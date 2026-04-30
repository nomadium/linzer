# frozen_string_literal: true

# Rack integration for Linzer.
#
# XXX

require "rack"
require "linzer"
require "rack/auth/signature"
require "linzer/message/adapter/rack/common"
require "linzer/message/adapter/rack/request"
require "linzer/message/adapter/rack/response"

Linzer::Message.register_adapter(Rack::Request,  Linzer::Message::Adapter::Rack::Request)
Linzer::Message.register_adapter(Rack::Response, Linzer::Message::Adapter::Rack::Response)
