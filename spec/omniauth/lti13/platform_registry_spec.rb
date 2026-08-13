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

  # Two registrations sharing an issuer -- e.g. two Canvas tenants, both
  # under Canvas Cloud's shared https://canvas.instructure.com issuer.
  let(:canvas_tenant_a_attrs) { canvas_attrs.merge(client_id: "tenant-a-client-id") }
  let(:canvas_tenant_b_attrs) { canvas_attrs.merge(client_id: "tenant-b-client-id") }

  describe "#initialize" do
    it "raises when two registrations share the same (issuer, client_id) pair" do
      expect { described_class.new([canvas_attrs, canvas_attrs]) }.to raise_error(ArgumentError, /Duplicate/)
    end

    it "does not raise when two registrations share an issuer but have different client_ids" do
      expect { described_class.new([canvas_tenant_a_attrs, canvas_tenant_b_attrs]) }.not_to raise_error
    end
  end

  describe "#find" do
    it "returns the matching Platform when exactly one is registered for that issuer" do
      registry = described_class.new([canvas_attrs])

      platform = registry.find(issuer: "https://canvas.example.edu")

      expect(platform).to be_a(OmniAuth::Lti13::Platform)
      expect(platform.client_id).to eq("canvas-client-id")
    end

    it "picks the correct platform by issuer when multiple are registered under different issuers" do
      registry = described_class.new([canvas_attrs, blackboard_attrs])

      expect(registry.find(issuer: "https://blackboard.example.edu").client_id).to eq("blackboard-client-id")
      expect(registry.find(issuer: "https://canvas.example.edu").client_id).to eq("canvas-client-id")
    end

    it "returns nil for an unregistered issuer rather than a default" do
      registry = described_class.new([canvas_attrs])

      expect(registry.find(issuer: "https://unregistered.example.edu")).to be_nil
    end

    it "returns nil for a blank issuer" do
      registry = described_class.new([canvas_attrs])

      expect(registry.find(issuer: nil)).to be_nil
      expect(registry.find(issuer: "")).to be_nil
    end

    it "returns nil when no platforms are registered" do
      registry = described_class.new([])

      expect(registry.find(issuer: "https://canvas.example.edu")).to be_nil
    end

    context "when more than one platform shares an issuer (e.g. Canvas Cloud's shared issuer across tenants)" do
      it "resolves by client_id when given" do
        registry = described_class.new([canvas_tenant_a_attrs, canvas_tenant_b_attrs])

        platform = registry.find(issuer: "https://canvas.example.edu", client_id: "tenant-b-client-id")

        expect(platform.client_id).to eq("tenant-b-client-id")
      end

      it "returns nil when client_id is given but doesn't match any registration for that issuer" do
        registry = described_class.new([canvas_tenant_a_attrs, canvas_tenant_b_attrs])

        platform = registry.find(issuer: "https://canvas.example.edu", client_id: "some-other-client-id")

        expect(platform).to be_nil
      end

      it "raises AmbiguousPlatformError when client_id is omitted, rather than guessing" do
        registry = described_class.new([canvas_tenant_a_attrs, canvas_tenant_b_attrs])

        expect { registry.find(issuer: "https://canvas.example.edu") }
          .to raise_error(OmniAuth::Lti13::AmbiguousPlatformError)
      end
    end
  end
end
