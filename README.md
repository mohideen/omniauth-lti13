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

📖 **[Authentication flow walkthrough](docs/authentication-flow.md)** — sequence diagram and a
method-by-method trace of both legs of a launch.

## Requirements

- Ruby >= 3.2
- [`omniauth_openid_connect`](https://github.com/omniauth/omniauth_openid_connect) ~> 0.8 (the
  OIDC/JWT machinery this builds on)
- `activesupport`

## Installation

Not yet published to RubyGems, and not yet tagged. Add it from git:

```ruby
# pin to a specific commit until a release is tagged
gem "omniauth-lti13", git: "https://github.com/avalonmediasystem/omniauth-lti13.git"
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
strategy-wide config; they're resolved per-request, keyed on the incoming `iss` (and, when
needed, `client_id` -- see below), against the `:platforms` option. **This schema is this gem's
to define**, and is the primary interface boundary with whatever host app populates it (for
Avalon, from `settings.yml`).

`:platforms` is an Array of Hashes (or `OmniAuth::Lti13::Platform` instances), each with:

| Key                       | Type             | Required | Description                                                                 |
|----------------------------|------------------|----------|-------------------------------------------------------------------------------|
| `issuer`                  | String           | yes      | The Platform's `iss` value. Used to select this entry.                       |
| `client_id`                | String           | yes      | This tool's client_id as registered with the Platform.                       |
| `deployment_ids`           | Array\<String or Integer\> | yes | Every deployment_id this Platform is allowed to launch with. A Platform can have more than one deployment of the same tool registration. Compared against the token's deployment_id claim as strings, so an unquoted numeric YAML value (`deployment_ids: [1]`) works the same as a quoted one. |
| `authorization_endpoint`  | String           | yes      | The Platform's OIDC authorization endpoint (where the login redirect goes).   |
| `jwks_uri`                 | String           | yes      | The Platform's JWKS endpoint, for verifying id_token signatures.             |
| `redirect_uri`              | String           | yes      | This tool's registered callback URL for this Platform (`.../users/auth/lti/callback`). |

An `iss` that doesn't match any registered platform is **rejected**, not silently accepted or
matched against a default. A `client_id` mismatch (when the login-initiation request happens to
include one) and a `deployment_id` mismatch (from the verified id_token) are rejected the same
way.

**LTI identity is `(issuer, client_id, deployment_id)`, not `issuer` alone.** Canvas Cloud, for
example, uses a single shared issuer (`https://canvas.instructure.com`) across *every* tenant --
the exact issuer in the example above -- so two Canvas tenants can only both be registered here
if `client_id` disambiguates between them:

```ruby
platforms: [
  { issuer: "https://canvas.instructure.com", client_id: "tenant-a-client-id", ... },
  { issuer: "https://canvas.instructure.com", client_id: "tenant-b-client-id", ... },
]
```

Two registrations sharing the exact same `(issuer, client_id)` pair raise `ArgumentError` at
strategy-construction time. When an issuer matches more than one registration, the
login-initiation request's `client_id` param (RECOMMENDED by the IMS Security Framework for
exactly this case) picks the right one; if it's missing, resolution is genuinely ambiguous and
the launch is rejected (`OmniAuth::Lti13::AmbiguousPlatformError`) rather than guessing.

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
auth_hash.info.custom_<param>          # each parameter from the custom claim, under a
                                        # `custom_` prefix -- see "Custom parameters" below
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

#### Custom parameters

The LTI custom claim (`https://purl.imsglobal.org/spec/lti/claim/custom`) carries whatever
parameters were configured in the tool registration on the Platform — a campus username, an
internal user id, a department code. They arrive inside the signed `id_token`, so they are as
trustworthy as any other claim, and each is merged into `info` under a **`custom_` prefix**:

```ruby
# custom claim: { "canvas_user_id" => "1234", "department" => "Music Library" }
auth_hash.info.custom_canvas_user_id  # => "1234"
auth_hash.info.custom_department      # => "Music Library"
```

The prefix keeps the Platform's namespace and this gem's separate, which has two consequences:

- **A custom parameter can never shadow a standard `info` field.** One named `email`, `name`, or
  `nickname` lands on `custom_email` / `custom_name` / `custom_nickname`; the standard fields are
  only ever set from their own claims.
- **`info.email` comes from the standard `email` claim alone**, and is an explicit `nil` when the
  Platform doesn't send one. If your Platform releases email *only* as a custom parameter — some
  do — it will be at `info.custom_email`, and `info.email` will be nil. Read it from there, or
  configure the Platform to release the standard claim.

A Platform that sends something other than a JSON object for this claim is ignored rather than
allowed to raise: custom parameters are optional, and a malformed one shouldn't sink an
otherwise valid launch.

### What the host app must handle

These aren't gaps in this gem -- they're constraints of the surrounding stack (OmniAuth
middleware config is process-wide, not per-strategy; cookie policy is the app's), so they have
to be handled in the host app, not here:

- **CSRF exemption for the login-initiation route.** OmniAuth 2.x's
  `OmniAuth::AuthenticityTokenProtection` rejects cross-site request-phase POSTs by default --
  which is exactly what a real LTI third-party-initiated login is (a POST from the Platform,
  not your own site). It's controlled by `OmniAuth.config.request_validation_phase`, which is
  global. The host app needs to disable or scope this for the LTI login path.
- **GET support on the login-initiation route.** The IMS Security Framework requires the OIDC
  login-initiation endpoint to accept both GET and POST; OmniAuth 2.x defaults
  `OmniAuth.config.allowed_request_methods` to `[:post]` only (also global). Widen it to
  `[:get, :post]` if a Platform you support initiates via GET.
- **A session cookie that survives the cross-site callback POST** (`SameSite=None; Secure`).
  The launch spans two requests, and everything the callback needs to be trustworthy --
  `state`, `nonce`, and the resolved platform reference -- lives in the session between them.
  The Platform POSTs the callback from *its* origin, so a `SameSite=Lax` session cookie is not
  sent, the callback sees an empty session, and the launch fails. It fails **closed**, by
  design (see "Design notes" below), but the resulting error names the symptom rather than the
  cause:

  ```text
  /auth/failure?message=no+registered+LTI+platform+for+issuer+nil&strategy=lti
  ```

  If you see `issuer nil` in that message, suspect the cookie before suspecting the config.

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
- **Nonce/state replay protection**: both are session-based, one-time-use values. `state` is
  validated by `omniauth_openid_connect`; `nonce` is validated by this gem against the
  session-stored value only -- a `nonce` *request* param is never honored, since a real LTI
  Authentication Response never carries one (only `id_token` and `state` do) and JWTs aren't
  encrypted, so anyone holding a captured `id_token` could otherwise read its `nonce` claim and
  echo it back as a param to replay that token into a session of their own.
- **`response_mode=form_post`**, per the IMS Security Framework.

## Errors and troubleshooting

Every failure raises a subclass of `OmniAuth::Lti13::Error`, which OmniAuth turns into its
standard failure redirect (`/auth/failure?message=...`).

**Three of these carry deliberately generic messages**, because OmniAuth's
`fail!(e.message, e)` puts the message on that redirect, where the end user (and anything
logging URLs) can see it. Leaking our registered `client_id`, `issuer`, or `deployment_ids`
there would hand an attacker exactly the values needed to craft a better-formed forgery. The
specifics go to `OmniAuth.logger` at `warn` instead -- **when diagnosing a rejected launch,
read the log, not the redirect.**

| Error | Raised when | Message detail |
|---|---|---|
| `UnregisteredPlatformError` | `iss` matches no registered platform (or, on the callback leg, no platform reference survived in the session) | names the issuer |
| `AmbiguousPlatformError` | `iss` matches several registrations and no `client_id` was supplied to disambiguate | names the issuer |
| `InvalidLoginInitiationError` | login initiation is missing `login_hint` and/or `target_link_uri` | names the missing params |
| `ClientIdMismatchError` | login initiation's `client_id` is present but doesn't match the resolved platform | **generic** -- details logged |
| `DeploymentMismatchError` | the token's `deployment_id` isn't registered for the resolved platform, or is absent | **generic** -- details logged |
| `InvalidAzpError` | the token's `azp` is present but isn't our `client_id` | **generic** -- details logged |
| `DisallowedAlgorithmError` | the token is signed with anything other than `RS256` (including `none`) | names the algorithm |
| `ExpiredTokenError` | the token is past `exp` even allowing for `clock_skew` | names the expiry |
| `InvalidIdTokenError` | `iss`, `aud`, `nonce`, or `iat` failed validation | names the failing claim |

A known-issuer-but-unknown-`client_id` lookup surfaces as `UnregisteredPlatformError` (its
message blames the issuer), so that case additionally logs a warning naming `client_id` --
again, the log is what distinguishes the two.

## Design notes: why we override the base class

This gem subclasses `OmniAuth::Strategies::OpenIDConnect` and overrides six of its parents'
methods -- five from the OIDC strategy, plus `setup_phase` from `OmniAuth::Strategy`. They fall
into two groups.

**Two are extension points**, where the base class is fine and this strategy simply has
LTI-specific work to do at that point in the lifecycle. `request_phase` validates the
login-initiation request and stashes the resolved platform reference in the session, then calls
`super` for the actual redirect building. `setup_phase` resolves this request's Platform and
applies it to `client_options`/`issuer`; it does *not* call `super`, which has one consequence
worth knowing about -- see "The `:setup` option" at the end of this section.

**The other four replace base behavior that is wrong _for LTI specifically_** -- not buggy in
general. Those are the ones detailed below, collected here so the strategy source can stay
focused on flow. (Grouping is by *why* each override exists, not by whether it calls `super`:
`decode_id_token` wraps `super` with a retry but still belongs to this group.)

**`verify_id_token!` -- reimplemented rather than calling `super`.** The base delegates to
`OpenIDConnect::ResponseObject::IdToken#verify!`, which checks `exp` with no clock-skew
tolerance and raises immediately, inside a single expression with no seam to intercept. There
is no way to layer skew tolerance *on top of* an already-stricter check, so the check has to be
replaced rather than wrapped. Since `iss`/`aud`/`nonce` then need reimplementing anyway, all
id_token claim validation lives in one auditable place -- and `azp`, which the base never
checks at all, is validated alongside them.

**`decode_id_token` -- one retry with a forced JWKS re-fetch.** The base's own
`JSON::JWK::Set::KidNotFound` handling only retries *locally*, trying each already-fetched key,
and only for tokens with no `kid`; when a `kid` is present but unmatched it re-raises
immediately. It never re-fetches. A Platform that rotates its signing key would therefore fail
every launch until whatever populated the in-memory JWKS happened to restart. The override
clears the base's memoized `@public_key`/`@fetch_key` and retries exactly once.

**`validate_client_algorithm!` -- unconditional allowlist.** The base's algorithm check is
opt-in: it only runs when `client_signing_alg` is explicitly configured, and then compares
against that single value. LTI mandates `RS256`, and `alg: none` must never be accepted, so
this runs unconditionally against an explicit allowlist instead.

**`id_token_callback_phase` -- full LTI `auth_hash`.** The base builds a bare-bones AuthHash
(uid/name/email only), bypassing its own `info`/`extra`/`uid` DSL and calling `call_app!`
inline, which leaves no seam to extend. The override builds the full `auth_hash` contract
documented above, and validates `deployment_id` before doing so.

**Platform resolution fails closed on the callback leg.** `iss`/`client_id` are read from the
request only during login initiation; the callback leg reads the values stashed in the session
by that first leg, and does *not* fall back to request params. A callback arriving without a
prior request phase (missing or wiped session) is therefore rejected outright rather than being
allowed to select a platform from an attacker-controlled `iss`. This is what makes a dropped
session cookie surface as `issuer nil` (see "What the host app must handle" above).

**The id_token is decoded twice per callback.** `verify_id_token!` decodes to validate claims,
then `id_token_callback_phase` decodes again to build the `auth_hash`. This is deliberate: the
JWKS fetch is memoized, so the second decode costs one signature verification and no I/O, and
keeping each method self-contained (rather than threading a decoded token between them) matches
the base class's own structure.

### The `:setup` option is not supported

`OmniAuth::Strategy#setup_phase` is not a no-op: it implements OmniAuth's `:setup` option,
calling `options[:setup].call(env)` for a callable or dispatching to `setup_path` otherwise.
This strategy's `setup_phase` **does not call `super`**, so passing `setup:` has no effect and
raises no error.

That is deliberate, because there is no ordering in which `:setup` composes safely with
per-request platform resolution:

- Calling `super` **first** would run the host's hook, and then `apply_platform!` would
  immediately overwrite `options.issuer` and every `client_options` field it sets. A host using
  `:setup` for its conventional purpose -- dynamic per-request client configuration -- would
  have that silently clobbered, which is worse than an unsupported option, because it looks like
  it should work.
- Calling `super` **last** would let the host's hook override the resolution that just ran. But
  that resolution *is* the trust boundary: `issuer`, `client_id`, and `jwks_uri` determine which
  Platform we accept tokens from. Handing a host hook the ability to rewrite them after
  validation would undo the point of the registry.

Configure platforms through the `:platforms` option instead, which is resolved per-request by
design. `option :setup` defaults to `false`, so an app that doesn't set it is unaffected.

## Development

After checking out the repo, run `bundle install`. Then:

```bash
bundle exec rake        # specs + rubocop (the default task)
bundle exec rspec       # specs only
bundle exec rubocop -a  # lint, autocorrecting what's safe
bin/console             # interactive prompt with the gem loaded
```

To install this gem onto your local machine, run `bundle exec rake install`.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
