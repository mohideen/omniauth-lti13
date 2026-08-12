# omniauth-lti13

An OmniAuth strategy implementing the [LTI 1.3](https://www.imsglobal.org/spec/lti/v1p3) Core
launch/auth flow (the OIDC third-party-initiated login used by Canvas, Blackboard, and other
LMS Platforms), built on top of [`omniauth_openid_connect`](https://github.com/omniauth/omniauth_openid_connect)
rather than reimplementing OIDC/JWT handling.

Built for [Avalon Media System](https://github.com/avalonmediasystem/avalon)'s upgrade from LTI
1.1 to 1.3 ([issue #6031](https://github.com/avalonmediasystem/avalon/issues/6031)), but has no
Avalon-specific code in it -- the `auth_hash` contract documented below happens to match what
Avalon's `User.find_for_lti` expects, but any Rails app using Devise/OmniAuth can consume it.

**Out of scope:** LTI Advantage (Deep Linking, Assignment and Grade Services, Names and Role
Provisioning Service). This gem implements Core launch/auth only.

## Installation

Not yet published to RubyGems. Add it from git:

```ruby
gem "omniauth-lti13", git: "https://github.com/avalonmediasystem/omniauth-lti13.git", tag: "v0.1.0"
```

or, for local development against a sibling checkout:

```ruby
gem "omniauth-lti13", path: "../omniauth-lti13"
```

## Usage

### Naming

The strategy class is `OmniAuth::Strategies::Lti13` -- not `OmniAuth::Strategies::Lti` -- so it
doesn't collide with the constant used by the LTI 1.1 `omniauth-lti` gem; both can be loaded in
the same app. `option :name` (not the class name) is what OmniAuth actually uses to pick the URL
path a strategy answers on, so it's set to `"lti"` independently, meaning this strategy answers
at `/auth/lti` by default (`/users/auth/lti` once Devise adds its usual path prefix).

Register it with an explicit `strategy_class:` rather than relying on OmniAuth/Devise's
constant-name-based autoload, so the class/name split above is unambiguous:

```ruby
# config/initializers/devise.rb
config.omniauth :lti,
  strategy_class: OmniAuth::Strategies::Lti13,
  platforms: [
    {
      issuer: "https://canvas.instructure.com",
      client_id: "10000000000001",
      deployment_ids: ["1:7db438071375c02373713c12c73869ff2f2011fe"],
      authorization_endpoint: "https://canvas.instructure.com/api/lti/authorize_redirect",
      jwks_uri: "https://canvas.instructure.com/api/lti/security/jwks",
      redirect_uri: "https://avalon.example.edu/users/auth/lti/callback",
    },
    # ... one entry per registered Platform
  ]
```

### Platform registration (`:platforms`)

A single instance of this gem may need to trust more than one LTI Platform -- e.g. several
Canvas accounts, or Canvas plus Blackboard. `client_options`/`issuer` therefore can't be static
strategy-wide config; they're resolved per-request, keyed on the incoming `iss`, against the
`:platforms` option. **This schema is this gem's to define**, and is the primary interface
boundary with whatever host app populates it (for Avalon, from `settings.yml`).

`:platforms` is an Array of Hashes (or `OmniAuth::Lti13::Platform` instances), each with:

| Key                       | Type             | Required | Description                                                                 |
|----------------------------|------------------|----------|-------------------------------------------------------------------------------|
| `issuer`                  | String           | yes      | The Platform's `iss` value. Used to select this entry.                       |
| `client_id`                | String           | yes      | This tool's client_id as registered with the Platform.                       |
| `deployment_ids`           | Array\<String\>  | yes      | Every deployment_id this Platform is allowed to launch with. A Platform can have more than one deployment of the same tool registration. |
| `authorization_endpoint`  | String           | yes      | The Platform's OIDC authorization endpoint (where the login redirect goes).   |
| `jwks_uri`                 | String           | yes      | The Platform's JWKS endpoint, for verifying id_token signatures.             |
| `redirect_uri`              | String           | yes      | This tool's registered callback URL for this Platform (`.../users/auth/lti/callback`). |

An `iss` that doesn't match any registered platform is **rejected**, not silently accepted or
matched against a default. A `client_id` mismatch (when the login-initiation request happens to
include one) and a `deployment_id` mismatch (from the verified id_token) are rejected the same
way.

### `clock_skew` (optional)

`option :clock_skew` (default `60`, seconds) bounds how much clock drift between this app and a
Platform is tolerated when validating the id_token's `exp`/`iat` claims. Pass a different value
if needed:

```ruby
config.omniauth :lti, strategy_class: OmniAuth::Strategies::Lti13, clock_skew: 120, platforms: [...]
```

### `auth_hash` contract

On a successful launch, `env["omniauth.auth"]` is populated with:

```ruby
auth_hash.uid                          # LTI `sub`
auth_hash.info.email                   # LTI `email` (nil if the Platform didn't send one)
auth_hash.extra.context_id             # context claim's `id`
auth_hash.extra.context_name           # context claim's `label`, falling back to `title`
                                        # if label is absent; explicit nil if neither is
                                        # present (not an absent key)
auth_hash.extra.context_title          # context claim's `title`, verbatim (additive; not
                                        # folded into context_name)
auth_hash.extra.consumer.context_label # context claim's `label`
auth_hash.extra.roles                  # roles claim, passed through unmodified
```

`context_name` deliberately prefers `label` over `title` -- this mirrors the LTI 1.1
`omniauth-lti` fork's behavior (`context_label` mapped to what became `Course.title`), so
instances upgrading from 1.1 don't see existing course titles change. `context_title` is
additive, exposing the full title separately for callers that want it.

### Two things this gem cannot do for you

These aren't gaps in this gem -- they're constraints of the OmniAuth middleware stack that
apply process-wide, not per-strategy, so they have to be handled in the host app's own
initializer, not here:

- **CSRF exemption for the login-initiation route.** OmniAuth 2.x's
  `OmniAuth::AuthenticityTokenProtection` rejects cross-site request-phase POSTs by default --
  which is exactly what a real LTI third-party-initiated login is (a POST from the Platform,
  not your own site). It's controlled by `OmniAuth.config.request_validation_phase`, which is
  global. The host app needs to disable or scope this for the LTI login path.
- **GET support on the login-initiation route.** The IMS Security Framework requires the OIDC
  login-initiation endpoint to accept both GET and POST; OmniAuth 2.x defaults
  `OmniAuth.config.allowed_request_methods` to `[:post]` only (also global). Widen it to
  `[:get, :post]` if a Platform you support initiates via GET.

## Security

- **Algorithm allowlist**: only `RS256` is accepted (per the IMS Security Framework), rejecting
  `alg: none` and everything else -- unconditionally, not just when a signing algorithm happens
  to be explicitly configured.
- **Clock-skew-tolerant `exp`/`iat`** validation (see `clock_skew` above).
- **`azp` validation**: when the id_token's optional `azp` claim is present, it must match the
  resolved platform's `client_id`.
- **JWKS rotation**: if the id_token's `kid` isn't found in the fetched JWKS, the JWKS is
  re-fetched once and verification retried, so a Platform that rotates its signing key doesn't
  fail every launch until something else happens to trigger a re-fetch.
- **Nonce/state replay protection** via `omniauth_openid_connect`: both are session-based,
  one-time-use values.
- **`response_mode=form_post`**, per the IMS Security Framework.

## Development

After checking out the repo, run `bundle install`. Then, run `bundle exec rspec` to run the
tests. You can also run `bin/console` for an interactive prompt.

To install this gem onto your local machine, run `bundle exec rake install`.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
