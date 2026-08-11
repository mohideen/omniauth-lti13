# frozen_string_literal: true

module OmniAuth
  module Lti13
    class Error < StandardError; end

    # Raised (and turned into a standard OmniAuth failure response by the
    # base OmniAuth::Strategy#call! rescue) when a launch or callback
    # arrives with an `iss` that doesn't match any configured platform.
    # Deliberately no fallback-to-default behavior here -- an unregistered
    # issuer must be rejected, not silently accepted.
    class UnregisteredPlatformError < Error
      def initialize(issuer)
        super("no registered LTI platform for issuer #{issuer.inspect}")
      end
    end

    # Raised when the login-initiation request's `client_id` is present but
    # doesn't match the resolved platform's configured client_id. `client_id`
    # is optional on the initiation request (RECOMMENDED by the IMS Security
    # Framework, for Platforms that register multiple clients under one
    # issuer), so this only fires when it's actually sent and wrong -- it's
    # never used to select the platform in the first place, only to catch a
    # mismatch against what issuer-based lookup already resolved.
    class ClientIdMismatchError < Error
      def initialize(expected, actual)
        super("login initiation client_id #{actual.inspect} does not match registered client_id #{expected.inspect}")
      end
    end

    # Raised when a login-initiation request is missing a parameter the IMS
    # OIDC third-party-initiated login spec requires (`login_hint`,
    # `target_link_uri`). Rejecting early here means a misbehaving Platform
    # gets a clear tool-side error instead of being silently redirected to
    # an authorization request that's already missing required data and
    # will only fail later, harder to diagnose, on the Platform's end.
    class InvalidLoginInitiationError < Error
      def initialize(missing_params)
        super("login initiation request missing required param(s): #{missing_params.join(', ')}")
      end
    end

    # Raised when the id_token's deployment_id claim doesn't match any of
    # the resolved platform's registered deployment_ids (or is missing).
    # iss and client_id are already covered by platform lookup + the base
    # class's own aud verification -- this closes the last leg (iss +
    # client_id + deployment_id together identify a registered deployment,
    # rather than collapsing them into one opaque key the way LTI 1.1's
    # oauth_consumer_key did).
    class DeploymentMismatchError < Error
      def initialize(issuer, deployment_id)
        super("deployment_id #{deployment_id.inspect} is not registered for issuer #{issuer.inspect}")
      end
    end
  end
end
