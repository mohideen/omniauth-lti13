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
  # Namespace for this gem's supporting types. The strategy itself lives at
  # OmniAuth::Strategies::Lti13, where OmniAuth expects to find strategies;
  # everything it leans on (Platform, PlatformRegistry, Claims, the error
  # hierarchy) is namespaced here.
  module Lti13
  end
end
