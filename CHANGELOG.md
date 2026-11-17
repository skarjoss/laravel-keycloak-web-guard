# CHANGELOG

All notable changes to this project will be documented in this file.

### [3.1.0] - Unreleased

Hardening release. Everything is backwards compatible; the new options have
safe defaults and can be tuned through the config file / environment.

* HTTP client: default `timeout` (5s) and `connect_timeout` (3s), plus
  conservative retries for `GET` requests (`cURL` errors 6/7/28/35/52/55/56 and
  5xx). Requests to the token endpoint are never replayed.
* User profile cached in the session (`profile_cache_ttl`), so the guard stops
  calling the `userinfo` endpoint on every request. The cache survives an access
  token rotation (refresh), so an outage right after a refresh does not log the
  user out.
* Graceful degradation (`profile_stale_ttl`): a Keycloak outage (network error,
  5xx, unreachable discovery) no longer logs the user out. A `4xx` response still
  invalidates the session, and an expired token is only tolerated when the
  refresh actually failed because of the network.
* The `keycloak.logout` route also invalidates the application session, not only
  the SSO token (relevant on shared computers).
* Token refresh: a network error keeps the session; only a rejected refresh
  token (`invalid_grant`) forgets it. Refresh rejections are logged with the
  HTTP status.
* `KeycloakAccessToken::verifySignature()`: optional RS256/384/512 signature
  verification with the realm public key, and a `leeway` for clock skew.
  Previously only `exp`, `iss` and `aud` were checked.
* Optional `use_userinfo = false`: build the profile from the ID token claims.
* `KeycloakWebGuard::logout()` and `login()` implemented, so `Auth::logout()`
  no longer throws `Call to undefined method ...::logout()`.
* Authorization states: multiple concurrent states with TTL and a bounded list
  (multiple tabs), `consumeState()` and a loop protection after
  `max_state_failures`.
* Callback: no longer logs the authorization `code` / `session_state` (live
  credentials); errors returned by Keycloak redirect the user instead of
  throwing a 500 page (`throw_callback_errors` to opt in to the old behaviour).
* **Security: the exception logger no longer dumps the HTTP request object**,
  which was writing the `Authorization: Bearer <access_token>` header into the
  application log. Only the method, URI, status and a truncated body are logged.
* **Security: the session id is regenerated after a successful callback** to
  prevent session fixation.
* `use_userinfo = false` without `verify_signature` falls back to `userinfo`
  (and logs a warning) instead of trusting unsigned ID token claims.
* `userinfo` subject is now checked against the ID token (before it was silently
  ignored).
* `validateState()` rejects non scalar input instead of casting it.
* `base64UrlDecode()` padding fixed for irregular token lengths.
* Log calls are resilient when the logger is not available.
* The session persistence failure is logged instead of being swallowed.
* The callback no longer loops to the identity provider when the authorization
  code cannot be exchanged.
* Added a PHPUnit suite (38 tests) and a GitHub Actions workflow. See
  [UPGRADING.md](UPGRADING.md) for the three defaults that change the behaviour.

### [3.0.1] - 2022-09-28

* Fix #79 (looping on KeycloakCan error). (props: @andrex47)

### [3.0.0] - 2022-09-23

* Support to Keycloak >= 18. (props: @serumk)

### [2.3.3] - 2022-03-20

* Support to Laravel 9.0. (props: @alvarofelipems)
* Allow access list roles in the Guard. (props: @socieboy)
* A typo in docs. (props: @atyakresna)

### [2.3.2] - 2021-01-27

* Support to Guzzle 7.

### [2.3.1] - 2021-01-27

* Fixed a problem in the expired check. (props: @gorkagv)

### [2.3.0] - 2020-10-30

* Support to Laravel 8.0. (props: @matthewhall-ca)
* Support to Laravel Gate.

### [2.2.0] - 2020-09-13

* Implementing more auth checks. (props for code review: @cyrillbolliger)
* Support to Laravel Gate.

### [2.1.1] - 2020-09-01

* Implementing state check on authorization flow. (props for code review: @cyrillbolliger)

Cyrill Bolliger alerted us today we were not using 'state' param on authentication request.
He did a responsible disclosure to sending a e-mail and we are very grateful (I hope pay him a beer/coffee someday).

### [2.1.0] - 2020-08-26

* ClientID as method to allow override

### [2.0.0] - 2020-06-01

* OpenID configuration refactored.

We'll request only if necessary.
It's a breaking change if you extend **Services/KeycloakService.php**.

Props: @matthewhall-ca

### [1.0.0 ~ 2.0.0] - 2020-06-05

We start CHANGELOG on 2.0.0 ...
So, here is a lot of changes to make the plugin stable.

* Configurations
* Auth based on Laravel
* Check of a role from Keycloak user profile
* Middleware for route access based on role
* Guzzle client options

### [1.0.0] - 2019-06-05

It's alive!

