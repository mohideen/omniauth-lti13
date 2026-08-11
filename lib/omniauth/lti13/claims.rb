# frozen_string_literal: true

module OmniAuth
  module Lti13
    # LTI 1.3 claim URIs used by this gem's claim mapping. Not exhaustive --
    # only the claims this gem actually reads (per the auth_hash contract
    # and deployment validation in lti-gem-prompt.md). LTI Advantage claims
    # (Deep Linking, AGS, NRPS) are deliberately not included; that's out of
    # scope for this gem.
    module Claims
      CONTEXT = "https://purl.imsglobal.org/spec/lti/claim/context"
      DEPLOYMENT_ID = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
      ROLES = "https://purl.imsglobal.org/spec/lti/claim/roles"
    end
  end
end
