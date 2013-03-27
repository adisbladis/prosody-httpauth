-- Backend to auth against a HTTP service
-- Copyright (C) 2012 Adam Höse <adis@blad.is>
-- 
-- This project is MIT/X11 licensed. Please see the
-- 
-- Example config:
-- httpBaseUrl = "http://localhost:6060/xmppauth"
-- authentication = "httpAuth"
-- 

local log = require "util.logger".init("auth_httpAuth");
local config_get = require "core.configmanager".get
local type = type;
local error = error;
local ipairs = ipairs;
local hashes = require "util.hashes";
local jid_bare = require "util.jid".bare;
local config = require "core.configmanager";
local new_sasl = require "util.sasl".new;
local hosts = hosts;

local baseUrl = config.get("*", "core", "httpBaseUrl");
local httpAuthSecret = config.get("*", "core", "httpAuthSecret")

local http = require("socket.http")
local ltn12 = require("ltn12")
local io = require("io")
local json = require("json")

local prosody = _G.prosody;

local function getJson(url)
      response = {}
      http.request {
	 url = url,
	 headers = {
	    ["X-prosody-httpAuth"] = httpAuthSecret
	 },
	 sink = ltn12.sink.table(response)
      };
      return json.decode(response[1]);
end

function new_default_provider(host)
   local provider = { name = "httpAuth" };

   function provider.test_password(username, password)
      log("debug", "Testing password")
      return getJson(baseUrl .. "/test_token/" .. username .. "/" .. username);
   end

   function provider.get_password(username)
      log("debug", "Getting password")
      return getJson(baseUrl .. "/get_token/" .. username);
   end

   function provider.set_password(username, password)
      log("debug", "Setting password")
      return nil, "Not implemented";
   end

   function provider.user_exists(username)
      log("debug", "Checking user");
      return getJson(baseUrl .. "/user_exists/" .. username);
   end

   function provider.create_user(username, password)
      log("debug", "Create user");
      return nil, "Not implemented";
   end

   function provider.delete_user(username)
      log("debug", "Deleting user");
      return nil, "Not implemented";
   end

   function provider.get_sasl_handler()
      local getpass_authentication_profile = {
	 plain = function(sasl, username, realm)
	    if provider.user_exists(username) then
	       return provider.get_password(username), true;
	    else
	       return false;
	    end
	 end
      }
      return new_sasl(module.host, getpass_authentication_profile);
   end

   return provider;

end

module:add_item("auth-provider", new_default_provider(module.host));
