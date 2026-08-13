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
    #
    # Methods are ordered by launch flow (shared setup -> request leg ->
    # callback leg -> auth_hash), not by visibility. Methods the framework
    # calls into are tagged "Framework hook"; the rest are ours. All six
    # tagged methods override a parent: two (setup_phase, request_phase)
    # are extension points where this strategy adds its own work, and four
    # replace base behavior that is wrong for LTI. The reasoning for every
    # one of them lives under "Design notes: why we override the base
    # class" in the README, so each carries only a one-line pointer here.
    class Lti13 < OmniAuth::Strategies::OpenIDConnect
      option :name, "lti"

      # Registered Platforms this instance trusts (schema: see README).
      # Resolved per-request in setup_phase by `iss` -- plus `client_id`
      # where registrations share an issuer, as Canvas Cloud's tenants do --
      # rather than being static config, since one instance may serve
      # several LMS deployments.
      option :platforms, []

      # LTI 1.3's launch is OIDC's implicit-style id_token flow, not the
      # authorization-code flow the base class defaults to: no token
      # endpoint round-trip. form_post is IMS-mandated -- the Platform POSTs
      # the id_token back rather than putting it in a redirect fragment.
      option :response_type, "id_token"
      option :response_mode, "form_post"

      # IMS-mandated round-trips: the Platform sends these on login
      # initiation and expects them echoed back unchanged. (login_hint is
      # also handled by the base class's authorize_uri; listed here so the
      # required set is visible in one place -- allow_authorize_params won't
      # clobber an already-set key.) client_id and deployment_id are
      # deliberately excluded: they're read for validation, never forwarded,
      # so an unauthenticated param can't overwrite the client_id that
      # platform lookup resolved.
      option :allow_authorize_params, %i[login_hint lti_message_hint target_link_uri]

      # Tolerance (seconds) for ordinary clock drift against the Platform
      # when checking exp/iat. Configurable; the allowlist below is not,
      # since the IMS Security Framework mandates RS256 specifically.
      option :clock_skew, 60

      # IMS Security Framework 1.0 section 5 mandates RS256; anything else,
      # "none" above all, is rejected. See "Design notes" for how this
      # differs from the base class's opt-in, single-value check.
      ALLOWED_ALGORITHMS = %i[RS256].freeze

      REQUIRED_INITIATION_PARAMS = %w[login_hint target_link_uri].freeze

      # The Platform resolved for the current request by setup_phase.
      attr_reader :current_platform

      # ---------------------------------------------------------------------
      # Shared setup -- runs on both legs
      # ---------------------------------------------------------------------

      # Built in the constructor, not lazily: OmniAuth's Strategy#call does
      # `dup.call!(env)`, so a `||=` in any per-request method would rebuild
      # the registry -- revalidating every configured Platform -- on every
      # launch and callback. Built here, it's computed once and carried into
      # each dup by Ruby's shallow ivar copy.
      def initialize(app, *args, &)
        super
        @platform_registry = OmniAuth::Lti13::PlatformRegistry.new(options.platforms)
      end

      # Framework hook (OmniAuth::Strategy), runs before both legs. Resolves
      # this request's Platform and applies it to `client_options`/`issuer`.
      # An unregistered or ambiguous issuer raises rather than falling back
      # to a default; the raise propagates through OmniAuth::Strategy#call!'s
      # rescue, becoming a standard OmniAuth failure response.
      #
      # Replaces the base implementation without calling super, so OmniAuth's
      # `:setup` option is deliberately unsupported here -- see "Design notes"
      # (the :setup option) for why it can't compose with this resolution.
      def setup_phase
        issuer = current_iss
        client_id = current_client_id
        consume_stashed_platform_ref! unless on_request_path?

        platform = platform_registry.find(issuer: issuer, client_id: client_id)
        raise OmniAuth::Lti13::UnregisteredPlatformError, issuer unless platform

        apply_platform!(platform)
      end

      private

      attr_reader :platform_registry

      # One-time use, mirroring omniauth.state/omniauth.nonce: once the
      # callback leg has read these, the attempt is finishing either way.
      def consume_stashed_platform_ref!
        session.delete("omniauth.lti13.iss")
        session.delete("omniauth.lti13.client_id")
      end

      # Read from the request only during login initiation, where `iss` is
      # guaranteed present per the IMS spec; the callback leg reads what the
      # request leg stashed and deliberately does *not* fall back to request
      # params. See "Design notes" (fails closed) for why, and for the
      # `issuer nil` symptom that produces.
      def current_iss
        on_request_path? ? request.params["iss"] : session["omniauth.lti13.iss"]
      end

      # Same fail-closed shape as current_iss. Disambiguates when a
      # Platform's issuer is shared across more than one registration.
      def current_client_id
        on_request_path? ? request.params["client_id"] : session["omniauth.lti13.client_id"]
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

      # ---------------------------------------------------------------------
      # Request leg -- third-party-initiated login
      # ---------------------------------------------------------------------

      # Framework hook (OIDC strategy). Validates the initiation request and
      # stashes the resolved platform reference for the callback leg, then
      # delegates to the base class's redirect building. Request-leg-only
      # concerns, hence here rather than in the shared setup_phase.
      def request_phase
        validate_login_initiation!(current_platform)
        session["omniauth.lti13.iss"] = current_platform.issuer
        session["omniauth.lti13.client_id"] = current_platform.client_id
        super
      end

      # Rejecting a malformed initiation before redirecting the browser gives
      # a clear tool-side error, rather than an authorization request already
      # missing data that fails later, less legibly, on the Platform's end.
      def validate_login_initiation!(platform)
        validate_client_id!(platform)

        missing = REQUIRED_INITIATION_PARAMS.select { |param| request.params[param].blank? }
        raise OmniAuth::Lti13::InvalidLoginInitiationError, missing unless missing.empty?
      end

      # client_id is optional on initiation (RECOMMENDED by the IMS Security
      # Framework for Platforms registering multiple clients under one
      # issuer), so this fires only when sent *and* wrong. Details logged,
      # message generic -- see the README's error table for why.
      def validate_client_id!(platform)
        incoming_client_id = request.params["client_id"]
        return if incoming_client_id.blank?
        return if incoming_client_id == platform.client_id

        log :warn, "login initiation client_id #{incoming_client_id.inspect} does not match registered " \
                   "client_id #{platform.client_id.inspect} for issuer #{platform.issuer.inspect}"
        raise OmniAuth::Lti13::ClientIdMismatchError
      end

      # ---------------------------------------------------------------------
      # Callback leg -- authentication response
      # ---------------------------------------------------------------------

      # Framework hook (OIDC strategy). Reimplemented rather than calling
      # super -- see "Design notes" (verify_id_token!).
      def verify_id_token!(id_token)
        return unless id_token

        validate_claims!(decode_id_token(id_token))
      end

      # Framework hook (OIDC strategy). Adds one retry with a forced JWKS
      # re-fetch -- see "Design notes" (decode_id_token). @public_key and
      # @fetch_key are the base class's memoized JWKS, cleared to force it.
      def decode_id_token(id_token)
        super
      rescue JSON::JWK::Set::KidNotFound
        @public_key = nil
        @fetch_key = nil
        super
      end

      # Framework hook (OIDC strategy), called from decode_id_token. Runs
      # unconditionally against an allowlist -- see "Design notes"
      # (validate_client_algorithm!).
      def validate_client_algorithm!(algorithm)
        return if ALLOWED_ALGORITHMS.include?(algorithm)

        raise OmniAuth::Lti13::DisallowedAlgorithmError.new(algorithm, ALLOWED_ALGORITHMS)
      end

      # Every id_token claim check, one per line, in one shape. See "Design
      # notes" for why these are reimplemented rather than delegated to
      # OpenIDConnect::ResponseObject::IdToken#verify!.
      def validate_claims!(decoded)
        validate_issuer!(decoded)
        validate_audience!(decoded)
        validate_nonce!(decoded)
        validate_expiry!(decoded)
        validate_issued_at!(decoded)
        validate_azp!(decoded)
      end

      def validate_issuer!(decoded)
        return if decoded.iss == options.issuer

        raise OmniAuth::Lti13::InvalidIdTokenError, "iss #{decoded.iss.inspect} does not match expected issuer"
      end

      def validate_audience!(decoded)
        return if Array(decoded.aud).include?(client_options.identifier)

        raise OmniAuth::Lti13::InvalidIdTokenError, "aud #{decoded.aud.inspect} does not include our client_id"
      end

      # Session-stored nonce only, never a `nonce` request param: a real LTI
      # Authentication Response carries only id_token and state, and JWTs
      # aren't encrypted -- honoring a param would let anyone holding a
      # captured token echo that token's own nonce claim back and replay it,
      # comparing the value against itself.
      def validate_nonce!(decoded)
        return if decoded.nonce == stored_nonce

        raise OmniAuth::Lti13::InvalidIdTokenError, "nonce does not match"
      end

      def validate_expiry!(decoded)
        return if decoded.exp.to_i + options.clock_skew.to_i >= Time.now.to_i

        raise OmniAuth::Lti13::ExpiredTokenError, decoded.exp
      end

      def validate_issued_at!(decoded)
        return if decoded.iat.to_i <= Time.now.to_i + options.clock_skew.to_i

        raise OmniAuth::Lti13::InvalidIdTokenError, "iat #{decoded.iat.inspect} is too far in the future"
      end

      # azp is optional per OIDC Core -- it only needs checking when present,
      # to disambiguate an aud with multiple values. The base class doesn't
      # check it at all. Details logged, message generic (see README).
      def validate_azp!(decoded)
        return if decoded.azp.blank?
        return if decoded.azp == client_options.identifier

        log :warn, "id_token azp #{decoded.azp.inspect} does not match expected client_id " \
                   "#{client_options.identifier.inspect}"
        raise OmniAuth::Lti13::InvalidAzpError
      end

      # Framework hook (OIDC strategy), the callback path for
      # response_type "id_token" -- always, here. Builds the full LTI
      # auth_hash instead of the base's bare-bones one; see "Design notes"
      # (id_token_callback_phase), including why decoding here as well as in
      # verify_id_token! is deliberate.
      def id_token_callback_phase
        claims = decode_id_token(params["id_token"]).raw_attributes
        validate_deployment!(claims)

        env["omniauth.auth"] = build_auth_hash(claims)
        call_app!
      end

      # Last leg of "iss + client_id + deployment_id identify a registered
      # deployment" -- the first two are covered by platform lookup and
      # validate_audience!. LTI 1.1 collapsed all three into one opaque
      # oauth_consumer_key; 1.3 keeps them distinct, so all three get
      # checked. Details logged, message generic (see README).
      def validate_deployment!(claims)
        deployment_id = claims[OmniAuth::Lti13::Claims::DEPLOYMENT_ID]
        return if current_platform.deployment_id?(deployment_id)

        log :warn, "deployment_id #{deployment_id.inspect} is not registered for issuer " \
                   "#{current_platform.issuer.inspect} (registered: #{current_platform.deployment_ids.inspect})"
        raise OmniAuth::Lti13::DeploymentMismatchError
      end

      # ---------------------------------------------------------------------
      # auth_hash construction
      # ---------------------------------------------------------------------

      # `claims` is the id_token's raw_attributes: an
      # ActiveSupport::HashWithIndifferentAccess of every claim in the token,
      # standard and LTI-specific alike.
      def build_auth_hash(claims)
        context = claims[OmniAuth::Lti13::Claims::CONTEXT] || {}
        label = context["label"].presence
        title = context["title"].presence

        AuthHash.new(
          provider: name,
          uid: claims["sub"],
          info: { email: claims["email"] },
          extra: {
            # label wins over title, preserving LTI 1.1 semantics where
            # Course.title held the label, not a full title; title is only a
            # fallback so a Course isn't lost when a Platform sends one
            # without the other. See the README's auth_hash contract first.
            context_id: context["id"],
            context_name: label || title,
            context_title: title,
            consumer: { context_label: label },
            roles: claims[OmniAuth::Lti13::Claims::ROLES],
          }
        )
      end
    end
  end
end
