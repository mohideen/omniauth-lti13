# frozen_string_literal: true

RSpec.describe OmniAuth::Lti13::PlatformRegistry do
  let(:canvas_attrs) do
    {
      issuer: "https://canvas.example.edu",
      client_id: "canvas-client-id",
      deployment_ids: ["1:abc123"],
      authorization_endpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
      jwks_uri: "https://canvas.example.edu/api/lti/security/jwks",
      redirect_uri: "https://tool.example.org/users/auth/lti/callback",
    }
  end

  let(:blackboard_attrs) do
    {
      issuer: "https://blackboard.example.edu",
      client_id: "blackboard-client-id",
      deployment_ids: ["deployment-1"],
      authorization_endpoint: "https://blackboard.example.edu/lti/authorize",
      jwks_uri: "https://blackboard.example.edu/lti/jwks",
      redirect_uri: "https://tool.example.org/users/auth/lti/callback",
    }
  end

  describe "#find_by_issuer" do
    it "returns the matching Platform when exactly one is registered" do
      registry = described_class.new([canvas_attrs])

      platform = registry.find_by_issuer("https://canvas.example.edu")

      expect(platform).to be_a(OmniAuth::Lti13::Platform)
      expect(platform.client_id).to eq("canvas-client-id")
    end

    it "picks the correct platform by issuer when multiple are registered" do
      registry = described_class.new([canvas_attrs, blackboard_attrs])

      expect(registry.find_by_issuer("https://blackboard.example.edu").client_id).to eq("blackboard-client-id")
      expect(registry.find_by_issuer("https://canvas.example.edu").client_id).to eq("canvas-client-id")
    end

    it "returns nil for an unregistered issuer rather than a default" do
      registry = described_class.new([canvas_attrs])

      expect(registry.find_by_issuer("https://unregistered.example.edu")).to be_nil
    end

    it "returns nil for a blank issuer" do
      registry = described_class.new([canvas_attrs])

      expect(registry.find_by_issuer(nil)).to be_nil
      expect(registry.find_by_issuer("")).to be_nil
    end

    it "returns nil when no platforms are registered" do
      registry = described_class.new([])

      expect(registry.find_by_issuer("https://canvas.example.edu")).to be_nil
    end
  end
end
