# UPGRADING

## 3.0.x → 3.1.0

3.1.0 is backwards compatible: no code change is required. All the new options
have safe defaults, but **three defaults change the behaviour** and should be
reviewed before deploying to production.

### 1. HTTP timeouts are enabled

A client without timeouts can block a PHP-FPM worker until the process is
killed when the identity provider hangs. The new defaults are:

```php
'http' => [
    'timeout' => 5,
    'connect_timeout' => 3,
    'retries' => 2,          // GET only
    'retry_delay_ms' => 200,
],
```

If your Keycloak is slow (or reachable only through a slow proxy), raise the
values in `config/keycloak-web.php` or the `.env` file:

```
KEYCLOAK_HTTP_TIMEOUT=10
KEYCLOAK_HTTP_CONNECT_TIMEOUT=5
```

Retries never apply to `POST` requests: authorization codes and rotating refresh
tokens are single use.

### 2. The user profile is cached in the session for 5 minutes

The guard no longer calls the `userinfo` endpoint on every request. As a
consequence, changes made to the name/e-mail of a user in Keycloak can take up
to `profile_cache_ttl` seconds to show up.

```
KEYCLOAK_PROFILE_CACHE_TTL=300   # 0 to restore the old behaviour
```

While Keycloak is unreachable (network error, 5xx, discovery down) the cached
profile is reused for `profile_stale_ttl` extra seconds instead of logging the
user out. **A `4xx` response still ends the session**, so a revoked token is
never kept alive.

Security note: during an outage a disabled user keeps access until
`profile_cache_ttl + profile_stale_ttl` seconds. Reduce `profile_stale_ttl`
(300 is a good value) if your accounts are revoked often. An expired token is
only tolerated when the refresh failed because of the network; a plain expired
token always ends the session.

### Latency during an outage

The worst case for a single remote call is
`connect_timeout + retries * timeout + retry delays` (about 15 seconds with the
defaults). If your identity provider is often unreachable, lower `retries` to 1
and/or `timeout` to 3 seconds to protect the PHP-FPM pool.

### 3. Errors from the authorization endpoint redirect instead of throwing

Before, an `error` returned by Keycloak (`access_denied`, `login_required`...)
threw a `KeycloakCallbackException` and rendered a 500 page. Now the user is
redirected with the error flashed. To keep the previous behaviour:

```
KEYCLOAK_THROW_CALLBACK_ERRORS=true
```

### Other behaviour changes

* The `sub` of `userinfo` is now compared with the ID token. It was silently
  ignored before. Keycloak always returns it, so no action is required.

### Security notes (action recommended)

* **Check your existing logs.** Before 3.1.0 a failed Keycloak request logged
  the whole HTTP request object, including the `Authorization: Bearer ...`
  header of the access token. If you ship logs to an external service or keep
  long retention, purge those entries or rotate the tokens.
* The session id is regenerated after a successful callback to prevent session
  fixation.
* `use_userinfo = false` requires `verify_signature = true`; without it the
  package falls back to `userinfo` instead of trusting unsigned claims.
* `KeycloakWebGuard::logout()` and `login()` are implemented, so
  `Auth::logout()` no longer throws `Call to undefined method`.
* Multiple authorization states are kept in the session (5 by default), which
  makes multiple tabs work. The old single state is still accepted.
* The callback no longer logs the authorization `code` or the `session_state`.

### Recommended hardening (opt-in)

```php
// config/keycloak-web.php
'verify_signature' => true,        // KEYCLOAK_VERIFY_SIGNATURE
'failure_redirect' => '/admin/login',
```

`verify_signature` validates the JWT with `KEYCLOAK_REALM_PUBLIC_KEY`. It is
required if you plan to disable the `userinfo` endpoint:

```php
'scopes' => 'openid email profile',
'use_userinfo' => false,
'verify_signature' => true,
```

### Deploying

1. `composer update skarjoss/laravel-keycloak-web-guard`
2. `php artisan config:clear` (or `config:cache` again)
3. If you published `config/keycloak-web.php`, copy the new keys from the
   package config file (`http`, `profile_cache_ttl`, `profile_stale_ttl`,
   `state_ttl`, `max_states`, `failure_redirect`, `max_state_failures`,
   `throw_callback_errors`, `scopes`, `leeway`, `verify_signature`,
   `use_userinfo`, `openid_cache_ttl`). Missing keys fall back to safe defaults.
4. Restart the queue workers / Horizon so they pick up the new code.
