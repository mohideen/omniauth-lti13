# frozen_string_literal: true

require "omniauth_openid_connect"

module OmniAuth
  module Strategies
    # LTI 1.3 Core (launch/auth) as an OmniAuth strategy, built on top of
    # OmniAuth::Strategies::OpenIDConnect rather than reimplementing OIDC/JWT
    # handling. LTI Advantage (Deep Linking, AGS, NRPS) is out of scope.
    #
    # Named `Lti13`, not `Lti`, so it doesn't collide with the constant used
    # by the LTI 1.1 `omniauth-lti` gem -- the two can be loaded side by
    # side. `option :name` is what OmniAuth actually uses to pick the URL
    # path a strategy answers on, independent of the class name, so it's set
    # explicitly to "lti" here to match Avalon's `:lti` provider key.
    class Lti13 < OmniAuth::Strategies::OpenIDConnect
      option :name, "lti"
    end
  end
end
