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

      # LTI 1.3 Core's launch flow is OIDC's implicit-style id_token flow,
      # not the authorization-code flow OmniAuth::Strategies::OpenIDConnect
      # defaults to -- there's no token endpoint round-trip. response_mode
      # is form_post per the IMS Security Framework (the Platform POSTs the
      # id_token back rather than appending it to a redirect fragment).
      option :response_type, "id_token"
      option :response_mode, "form_post"

      # login_hint and lti_message_hint are IMS-mandated round-trips: the
      # Platform sends them on the login-initiation request and expects them
      # echoed back unchanged on the authentication request. target_link_uri
      # is threaded through the same way, per this gem's own contract with
      # Avalon (see lti-gem-prompt.md). login_hint is technically already
      # handled unconditionally by the base class's authorize_uri -- listed
      # here too so the full set required by the flow is visible in one
      # place, since allow_authorize_params won't clobber an already-set key.
      #
      # client_id and deployment_id, also present on the login-initiation
      # request, are deliberately NOT in this list: they're read for
      # validation (see setup_phase) rather than forwarded, since letting an
      # unauthenticated request param overwrite the client_id our platform
      # lookup already resolved would defeat the point of that lookup.
      option :allow_authorize_params, %i[login_hint lti_message_hint target_link_uri]

      REQUIRED_INITIATION_PARAMS = %w[login_hint target_link_uri].freeze

      # The Platform resolved for the current request by setup_phase.
      attr_reader :current_platform

      # Runs before both request_phase and callback_phase. Selects
      # `client_options`/`issuer` for this request based on the incoming
      # `iss`, looked up against the registered `:platforms` list. An
      # unregistered issuer raises rather than falling back to a default;
      # the raise propagates out through OmniAuth::Strategy#call!'s own
      # rescue, which turns it into a standard OmniAuth failure response.
      # On the request-phase leg only, also validates the login-initiation
      # request itself (required params present, client_id consistent).
      def setup_phase
        platform = platform_registry.find_by_issuer(current_iss)
        raise OmniAuth::Lti13::UnregisteredPlatformError, current_iss unless platform

        if on_request_path?
          validate_login_initiation!(platform)
          session["omniauth.lti13.iss"] = platform.issuer
        end

        apply_platform!(platform)
      end

      # Overrides OmniAuth::Strategies::OpenIDConnect#id_token_callback_phase
      # (the callback path taken when response_type is "id_token", which is
      # always, here). The base implementation builds a bare-bones AuthHash
      # (uid/name/email only); this builds the full LTI auth_hash contract
      # instead, and validates deployment_id before doing so. decode_id_token
      # re-verifies iss/aud/nonce/signature -- already done once by
      # verify_id_token! earlier in callback_phase, but it's a cheap decode
      # and keeping this method self-contained (rather than threading the
      # already-decoded token through) matches the base class's own
      # structure.
      def id_token_callback_phase
        claims = decode_id_token(params["id_token"]).raw_attributes
        validate_deployment!(claims)

        env["omniauth.auth"] = build_auth_hash(claims)
        call_app!
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

      # Rejecting a malformed login-initiation request here, before ever
      # redirecting the browser to the Platform, gives a clear tool-side
      # error instead of silently sending an authorize request that's
      # already missing data required by the flow.
      def validate_login_initiation!(platform)
        validate_client_id!(platform)

        missing = REQUIRED_INITIATION_PARAMS.select { |param| request.params[param].to_s.empty? }
        raise OmniAuth::Lti13::InvalidLoginInitiationError, missing unless missing.empty?
      end

      # client_id is optional on the login-initiation request (RECOMMENDED
      # by the IMS Security Framework for Platforms that register multiple
      # clients under one issuer) -- only rejects when it's present and
      # actually wrong, never used to pick the platform in the first place.
      def validate_client_id!(platform)
        incoming_client_id = request.params["client_id"]
        return if incoming_client_id.to_s.empty?
        return if incoming_client_id == platform.client_id

        raise OmniAuth::Lti13::ClientIdMismatchError.new(platform.client_id, incoming_client_id)
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

      # iss and client_id are already covered by platform lookup (setup_phase)
      # and the base class's own aud verification (verify_id_token!, earlier
      # in callback_phase) -- this is the last leg of "iss + client_id +
      # deployment_id together identify a registered deployment" from the
      # prompt: reject if the token's deployment_id isn't one of the
      # resolved platform's registered deployment_ids (including if it's
      # simply missing from the token).
      def validate_deployment!(claims)
        deployment_id = claims[OmniAuth::Lti13::Claims::DEPLOYMENT_ID]
        return if current_platform.deployment_id?(deployment_id)

        raise OmniAuth::Lti13::DeploymentMismatchError.new(current_platform.issuer, deployment_id)
      end

      # `claims` is the id_token's raw_attributes: an
      # ActiveSupport::HashWithIndifferentAccess (json-jwt's JSON::JWT base
      # class) containing every claim in the token, standard and
      # LTI-specific alike.
      def build_auth_hash(claims)
        context = claims[OmniAuth::Lti13::Claims::CONTEXT] || {}
        label = presence(context["label"])
        title = presence(context["title"])

        AuthHash.new(
          provider: name,
          uid: claims["sub"],
          info: {
            email: claims["email"],
          },
          extra: {
            # label wins over title -- deliberately preserves 1.1 semantics,
            # where Course.title held the context label, not a full title.
            # title is only a fallback for a Platform that sends a title but
            # no label, so a Course isn't lost. See lti-gem-prompt.md's
            # "Course title/label semantics" section before changing this.
            context_id: context["id"],
            context_name: label || title,
            context_title: title,
            consumer: { context_label: label },
            roles: claims[OmniAuth::Lti13::Claims::ROLES],
          }
        )
      end

      def presence(value)
        return nil if value.nil?
        return nil if value.respond_to?(:empty?) && value.empty?

        value
      end
    end
  end
end
