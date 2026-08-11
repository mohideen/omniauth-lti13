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

      # Registered Platforms this Avalon instance trusts, as an Array of
      # Hashes (or OmniAuth::Lti13::Platform instances) -- see the README
      # for the schema. A single instance may serve multiple LMS
      # deployments, so `client_options`/`issuer` can't be static
      # strategy-wide config; they're resolved per-request in setup_phase
      # below, keyed on the incoming `iss`.
      option :platforms, []

      # The Platform resolved for the current request by setup_phase.
      attr_reader :current_platform

      # Runs before both request_phase and callback_phase. Selects
      # `client_options`/`issuer` for this request based on the incoming
      # `iss`, looked up against the registered `:platforms` list. An
      # unregistered issuer raises rather than falling back to a default;
      # the raise propagates out through OmniAuth::Strategy#call!'s own
      # rescue, which turns it into a standard OmniAuth failure response.
      def setup_phase
        platform = platform_registry.find_by_issuer(current_iss)
        raise OmniAuth::Lti13::UnregisteredPlatformError, current_iss unless platform

        apply_platform!(platform)
        session["omniauth.lti13.iss"] = platform.issuer if on_request_path?
      end

      private

      # `iss` is guaranteed present on the initial (request-phase) launch,
      # per the IMS OIDC third-party-initiated login spec. Platforms aren't
      # guaranteed to resend it on the callback, so that leg prefers the
      # issuer stashed in the session during the request phase.
      def current_iss
        return request.params["iss"] if on_request_path?

        session["omniauth.lti13.iss"] || request.params["iss"]
      end

      def platform_registry
        @platform_registry ||= OmniAuth::Lti13::PlatformRegistry.new(options.platforms)
      end

      def apply_platform!(platform)
        @current_platform = platform
        options.issuer = platform.issuer
        client_options = options.client_options
        client_options.identifier = platform.client_id
        client_options.redirect_uri = platform.redirect_uri
        client_options.authorization_endpoint = platform.authorization_endpoint
        client_options.jwks_uri = platform.jwks_uri
      end
    end
  end
end
