require "rack"
require "rack/contrib"
require "linzer"
require_relative "myapp"

set :root, File.dirname(__FILE__)

use Rack::Auth::Signature, except: "/",
  config_path: "http-signatures.yml"

run Sinatra::Application
