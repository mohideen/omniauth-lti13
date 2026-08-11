# frozen_string_literal: true

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

  it "is a subclass of OmniAuth::Strategies::OpenIDConnect" do
    expect(described_class.superclass).to eq(OmniAuth::Strategies::OpenIDConnect)
  end

  it "answers on the 'lti' path, not the inherited 'openid_connect' path" do
    expect(strategy.options.name).to eq("lti")
  end

  describe "request-phase platform resolution" do
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

    def post_to_request_phase(platforms:, iss:)
      rack_app = Rack::Builder.new do
        use OmniAuth::Strategies::Lti13, platforms: platforms
        run ->(_env) { [404, {}, ["Not Found"]] }
      end.to_app

      env = Rack::MockRequest.env_for(
        "/auth/lti?iss=#{CGI.escape(iss)}", method: "POST", "rack.session" => {}
      )
      Rack::MockResponse.new(*rack_app.call(env))
    end

    it "mounts at /auth/lti and redirects to the resolved platform's authorization endpoint " \
       "(Avalon/Devise then prefixes this with /users)" do
      response = post_to_request_phase(platforms: [canvas_platform], iss: canvas_platform[:issuer])

      expect(response.status).to eq(302)
      expect(response.location).to start_with(canvas_platform[:authorization_endpoint])
    end

    it "selects the correct platform by iss when multiple are registered" do
      response = post_to_request_phase(
        platforms: [canvas_platform, blackboard_platform], iss: blackboard_platform[:issuer]
      )

      expect(response.status).to eq(302)
      expect(response.location).to start_with(blackboard_platform[:authorization_endpoint])
    end

    it "rejects a launch from an unregistered iss instead of falling back to a default" do
      response = post_to_request_phase(platforms: [canvas_platform], iss: "https://unregistered.example.edu")

      expect(response.status).to eq(302)
      expect(response.location).to start_with("/auth/failure")
      expect(response.location).to include("no+registered+LTI+platform")
    end
  end
end
