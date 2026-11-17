<?php

return [
    /**
     * Keycloak Url
     *
     * Generally https://your-server.com/auth
     */
    'base_url' => env('KEYCLOAK_BASE_URL', ''),

    /**
     * Keycloak Realm
     *
     * Default is master
     */
    'realm' => env('KEYCLOAK_REALM', 'master'),

    /**
     * The Keycloak Server realm public key (string).
     *
     * @see Keycloak >> Realm Settings >> Keys >> RS256 >> Public Key
     */
    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),

    /**
     * Keycloak Client ID
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_id' => env('KEYCLOAK_CLIENT_ID', null),

    /**
     * Keycloak Client Secret
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', null),

    /**
     * We can cache the OpenId Configuration
     * The result from /realms/{realm-name}/.well-known/openid-configuration
     *
     * @link https://www.keycloak.org/docs/3.2/securing_apps/topics/oidc/oidc-generic.html
     */
    'cache_openid' => env('KEYCLOAK_CACHE_OPENID', false),

    /**
     * TTL (seconds) of the cached OpenId configuration.
     * Null keeps the previous behaviour (cached forever).
     */
    'openid_cache_ttl' => env('KEYCLOAK_OPENID_CACHE_TTL', null),

    /**
     * Page to redirect after callback if there's no "intent"
     *
     * @see Vizir\KeycloakWebGuard\Controllers\AuthController::callback()
     */
    'redirect_url' => '/admin',

    /**
     * Page to redirect when the SSO flow cannot be completed
     * (invalid state, callback error...). Null uses the login route.
     */
    'failure_redirect' => env('KEYCLOAK_FAILURE_REDIRECT', null),

    /**
     * Max consecutive failed state validations before sending the user to the
     * failure page (0 disables the protection).
     */
    'max_state_failures' => env('KEYCLOAK_MAX_STATE_FAILURES', 3),

    /**
     * Throw a KeycloakCallbackException when Keycloak returns an error on the
     * authorization endpoint. When false the user is redirected with the error.
     */
    'throw_callback_errors' => env('KEYCLOAK_THROW_CALLBACK_ERRORS', false),

    /**
     * Scopes requested on the authorization endpoint.
     * Add "email profile" if you plan to disable "use_userinfo".
     */
    'scopes' => env('KEYCLOAK_SCOPES', 'openid'),

    /**
     * The routes for authenticate
     *
     * Accept a string as the first parameter of route() or false to disable the route.
     *
     * The routes will receive the name "keycloak.{route}" and login/callback are required.
     * So, if you make it false, you shoul register a named 'keycloak.login' route and extend
     * the Vizir\KeycloakWebGuard\Controllers\AuthController controller.
     */
    'routes' => [
        'login' => 'login',
        'logout' => 'logout',
        'register' => 'register',
        'callback' => 'callback',
    ],

    /**
    * GuzzleHttp Client options
    *
    * @link http://docs.guzzlephp.org/en/stable/request-options.html
    */
   'guzzle_options' => [],

    /**
     * HTTP options for the Keycloak client.
     *
     * Without a timeout a hung connection to the identity provider blocks a
     * PHP worker until the process is killed, which can take the whole site
     * down when the PHP-FPM pool is exhausted.
     *
     * "retries" only applies to GET requests (discovery and userinfo): POST
     * requests to the token endpoint are never replayed.
     *
     * These values are merged with "guzzle_options" (which wins).
     */
    'http' => [
        'timeout' => env('KEYCLOAK_HTTP_TIMEOUT', 5),
        'connect_timeout' => env('KEYCLOAK_HTTP_CONNECT_TIMEOUT', 3),
        'retries' => env('KEYCLOAK_HTTP_RETRIES', 2),
        'retry_delay_ms' => env('KEYCLOAK_HTTP_RETRY_DELAY_MS', 200),
    ],

    /**
     * Clock skew tolerance (seconds) used to refresh the access token before
     * it expires and to accept slightly out of date ID tokens.
     */
    'leeway' => env('KEYCLOAK_LEEWAY', 60),

    /**
     * TTL (seconds) of the user profile cached in the session. This avoids
     * calling the userinfo endpoint on every single request.
     *
     * 0 disables the cache.
     */
    'profile_cache_ttl' => env('KEYCLOAK_PROFILE_CACHE_TTL', 300),

    /**
     * Extra TTL (seconds) where the cached profile is still usable when
     * Keycloak cannot be reached, so a network hiccup does not log users out.
     */
    'profile_stale_ttl' => env('KEYCLOAK_PROFILE_STALE_TTL', 900),

    /**
     * Set to false to build the user profile from the ID token claims and stop
     * calling the userinfo endpoint. Requires "verify_signature", the realm
     * public key and the "email" + "profile" scopes.
     */
    'use_userinfo' => env('KEYCLOAK_USE_USERINFO', true),

    /**
     * Verify the JWT signature of the tokens with the realm public key.
     * Recommended when "use_userinfo" is disabled.
     */
    'verify_signature' => env('KEYCLOAK_VERIFY_SIGNATURE', false),

    /**
     * Allowed JWT signing algorithms for signature verification.
     */
    'signature_algorithms' => ['RS256'],

    /**
     * TTL (seconds) of the authorization states stored in the session and max
     * amount of concurrent states (multiple tabs).
     */
    'state_ttl' => env('KEYCLOAK_STATE_TTL', 600),
    'max_states' => env('KEYCLOAK_MAX_STATES', 5),
];
