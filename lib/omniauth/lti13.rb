# frozen_string_literal: true

# blank?/presence -- declared as an explicit dependency in the gemspec
# rather than relying on it arriving transitively via json-jwt/openid_connect.
require "active_support/core_ext/object/blank"

require_relative "lti13/version"
require_relative "lti13/errors"
require_relative "lti13/claims"
require_relative "lti13/platform"
require_relative "lti13/platform_registry"
require_relative "strategies/lti13"

module OmniAuth
  module Lti13
  end
end
