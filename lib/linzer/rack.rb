# frozen_string_literal: true

# Rack integration for Linzer.
#
# Require this file to enable Rack support. It loads the Rack adapter
# classes and registers them so that {Rack::Request} and {Rack::Response}
# objects can be used directly with the Linzer signing and verification API.
#
# @example
#   require "linzer/rack"
#
#   use Rack::Auth::Signature,
#     except: "/login",
#     default: :my_key

require "rack"
require "linzer"
require "rack/auth/signature"
require "linzer/message/adapter/rack/common"
require "linzer/message/adapter/rack/request"
require "linzer/message/adapter/rack/response"

Linzer::Message.register_adapter(Rack::Request,  Linzer::Message::Adapter::Rack::Request)
Linzer::Message.register_adapter(Rack::Response, Linzer::Message::Adapter::Rack::Response)
