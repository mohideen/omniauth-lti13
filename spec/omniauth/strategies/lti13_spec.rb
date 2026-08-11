# frozen_string_literal: true

require "cgi"
require "uri"

RSpec.describe OmniAuth::Strategies::Lti13 do
  let(:app) { ->(_env) { [404, {}, ["Not Found"]] } }

  subject(:strategy) { described_class.new(app) }

  let(:canvas_platform) do
    {
      issuer: "https://canvas.example.edu",
      client_id: "canvas-client-id",
      deployment_ids: ["1:abc123"],
      authorization_endpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
      jwks_uri: "https://canvas.example.edu/api/lti/security/jwks",
      redirect_uri: "https://tool.example.org/users/auth/lti/callback",
    }
  end

  let(:blackboard_platform) do
    {
      issuer: "https://blackboard.example.edu",
      client_id: "blackboard-client-id",
      deployment_ids: ["deployment-1"],
      authorization_endpoint: "https://blackboard.example.edu/lti/authorize",
      jwks_uri: "https://blackboard.example.edu/lti/jwks",
      redirect_uri: "https://tool.example.org/users/auth/lti/callback",
    }
  end

  let(:valid_initiation_params) do
    {
      login_hint: "canvas-user-42",
      target_link_uri: "https://tool.example.org/users/auth/lti",
      lti_message_hint: "opaque-platform-generated-hint",
    }
  end

  it "is a subclass of OmniAuth::Strategies::OpenIDConnect" do
    expect(described_class.superclass).to eq(OmniAuth::Strategies::OpenIDConnect)
  end

  it "answers on the 'lti' path, not the inherited 'openid_connect' path" do
    expect(strategy.options.name).to eq("lti")
  end

  describe "request phase (third-party initiated login)" do
    # OmniAuth 2.x's OmniAuth::AuthenticityTokenProtection rejects
    # cross-site request-phase POSTs by default -- which is exactly what a
    # real LTI third-party-initiated login is. That check is global
    # (OmniAuth.config.request_validation_phase), not per-strategy, so a
    # scoped exemption for the LTI login-initiation route is Avalon's
    # integration responsibility, not something this gem can/should do.
    # Disabled here only so these specs can test routing/resolution, not
    # that concern.
    around do |example|
      original_validation_phase = OmniAuth.config.request_validation_phase
      OmniAuth.config.request_validation_phase = nil
      example.run
      OmniAuth.config.request_validation_phase = original_validation_phase
    end

    def post_to_request_phase(platforms:, params:)
      rack_app = Rack::Builder.new do
        use OmniAuth::Strategies::Lti13, platforms: platforms
        run ->(_env) { [404, {}, ["Not Found"]] }
      end.to_app

      query = params.map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join("&")
      env = Rack::MockRequest.env_for("/auth/lti?#{query}", method: "POST", "rack.session" => {})
      Rack::MockResponse.new(*rack_app.call(env))
    end

    def redirect_query_params(response)
      URI.decode_www_form(URI(response.location).query).to_h
    end

    it "mounts at /auth/lti and redirects to the resolved platform's authorization endpoint " \
       "(Avalon/Devise then prefixes this with /users)" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer])
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with(canvas_platform[:authorization_endpoint])
    end

    it "selects the correct platform by iss when multiple are registered" do
      response = post_to_request_phase(
        platforms: [canvas_platform, blackboard_platform],
        params: valid_initiation_params.merge(iss: blackboard_platform[:issuer])
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with(blackboard_platform[:authorization_endpoint])
    end

    it "rejects a launch from an unregistered iss instead of falling back to a default" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: "https://unregistered.example.edu")
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
      expect(response.location).to include("no+registered+LTI+platform")
    end

    it "builds the authorization request with response_type=id_token and response_mode=form_post" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer])
      )

      redirect_params = redirect_query_params(response)

      expect(redirect_params["response_type"]).to eq("id_token")
      expect(redirect_params["response_mode"]).to eq("form_post")
      expect(redirect_params["scope"]).to eq("openid")
    end

    it "threads login_hint, lti_message_hint, and target_link_uri through to the authorization request " \
       "unmodified, without dropping lti_message_hint" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer])
      )

      redirect_params = redirect_query_params(response)

      expect(redirect_params["login_hint"]).to eq(valid_initiation_params[:login_hint])
      expect(redirect_params["lti_message_hint"]).to eq(valid_initiation_params[:lti_message_hint])
      expect(redirect_params["target_link_uri"]).to eq(valid_initiation_params[:target_link_uri])
    end

    it "does not forward the login-initiation client_id param as an authorize param, since the " \
       "resolved platform's registered client_id already drives the authorization request" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer], client_id: canvas_platform[:client_id])
      )

      redirect_params = redirect_query_params(response)

      expect(redirect_params["client_id"]).to eq(canvas_platform[:client_id])
    end

    it "rejects a login-initiation client_id that doesn't match the resolved platform's registered client_id" do
      response = post_to_request_phase(
        platforms: [canvas_platform],
        params: valid_initiation_params.merge(iss: canvas_platform[:issuer], client_id: "some-other-client-id")
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
      expect(response.location).to include("client_id")
    end

    it "rejects a login-initiation request missing required params (login_hint, target_link_uri)" do
      response = post_to_request_phase(platforms: [canvas_platform], params: { iss: canvas_platform[:issuer] })

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
      expect(response.location).to include("login_hint")
      expect(response.location).to include("target_link_uri")
    end
  end
end
