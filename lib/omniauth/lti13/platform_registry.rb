# frozen_string_literal: true

module OmniAuth
  module Lti13
    # Looks up a registered Platform by (issuer, client_id). Built from the
    # strategy's `:platforms` option (an Array of Hashes or Platform
    # instances) -- see the README for the config schema.
    #
    # LTI identity is (issuer, client_id, deployment_id), not issuer alone:
    # Canvas Cloud, for example, uses a single shared issuer
    # (https://canvas.instructure.com) across every tenant, so keying
    # lookups on issuer alone would let one tenant's registration silently
    # shadow another's. client_id therefore matters for *selecting* a
    # Platform here, not just for validating one already selected.
    class PlatformRegistry
      def initialize(platforms)
        @platforms = Array(platforms).map { |attrs| Platform.build(attrs) }

        duplicates = @platforms.group_by { |p| [p.issuer, p.client_id] }.select { |_key, group| group.size > 1 }
        return if duplicates.empty?

        described = duplicates.keys.map { |issuer, client_id| "issuer=#{issuer.inspect} client_id=#{client_id.inspect}" }
        raise ArgumentError, "Duplicate platform registration(s): #{described.join(', ')}"
      end

      # `client_id` disambiguates when more than one Platform shares an
      # issuer. It's optional on the LTI login-initiation request (per the
      # IMS Security Framework, RECOMMENDED specifically for this
      # multi-tenant-issuer case) -- if it's omitted and the issuer maps to
      # exactly one Platform, that's used; if it maps to more than one,
      # resolution is genuinely ambiguous and rejected outright rather than
      # guessing.
      def find(issuer:, client_id: nil)
        return nil if issuer.blank?

        matches = @platforms.select { |platform| platform.issuer == issuer }
        return nil if matches.empty?
        return matches.first if matches.one?

        raise OmniAuth::Lti13::AmbiguousPlatformError, issuer if client_id.blank?

        matches.find { |platform| platform.client_id == client_id }
      end
    end
  end
end
