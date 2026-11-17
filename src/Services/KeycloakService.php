<?php

namespace Vizir\KeycloakWebGuard\Services;

use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Vizir\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Vizir\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;

class KeycloakService
{
    /**
     * The Session key for token
     */
    const KEYCLOAK_SESSION = '_keycloak_token';

    /**
     * The Session key for state
     */
    const KEYCLOAK_SESSION_STATE = '_keycloak_state';

    /**
     * The Session key for the state list (multiple tabs)
     */
    const KEYCLOAK_SESSION_STATES = '_keycloak_states';

    /**
     * The Session key for the cached user profile
     */
    const KEYCLOAK_SESSION_PROFILE = '_keycloak_profile';

    /**
     * The Session key for failed state attempts
     */
    const KEYCLOAK_SESSION_STATE_FAILURES = '_keycloak_state_failures';

    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * CallbackUrl
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout
     *
     * @var array
     */
    protected $redirectLogout;

    /**
     * The state for authorization request
     *
     * @var string
     */
    protected $state;

    /**
     * The HTTP Client
     *
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * Scopes requested on the authorization endpoint
     *
     * @var string
     */
    protected $scopes;

    /**
     * TTL (seconds) of the cached user profile. 0 disables the cache.
     *
     * @var int
     */
    protected $profileCacheTtl;

    /**
     * Extra TTL (seconds) where a cached profile is still usable when Keycloak
     * cannot be reached (graceful degradation).
     *
     * @var int
     */
    protected $profileStaleTtl;

    /**
     * TTL (seconds) of the stored authorization states
     *
     * @var int
     */
    protected $stateTtl;

    /**
     * Max amount of concurrent authorization states kept in session
     *
     * @var int
     */
    protected $maxStates;

    /**
     * Verify the JWT signature of the tokens with the realm public key
     *
     * @var bool
     */
    protected $verifySignature;

    /**
     * Call the userinfo endpoint (or build the profile from the ID token)
     *
     * @var bool
     */
    protected $useUserinfo;

    /**
     * Clock skew tolerance (seconds)
     *
     * @var int
     */
    protected $leeway;

    /**
     * Whether the last token refresh failed because Keycloak is unreachable
     *
     * @var bool
     */
    protected $lastRefreshNetworkError = false;

    /**
     * Avoid flooding the log when the session handler fails
     *
     * @var bool
     */
    protected $sessionFailureLogged = false;

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @param ClientInterface $client
     * @return void
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(Config::get('keycloak-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = Config::get('keycloak-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = Config::get('keycloak-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = Config::get('keycloak-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = Config::get('keycloak-web.cache_openid', false);
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('keycloak.callback');
        }

        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = Config::get('keycloak-web.redirect_logout');
        }

        if (is_null($this->scopes)) {
            $this->scopes = (string) Config::get('keycloak-web.scopes', 'openid');
        }

        $this->profileCacheTtl = (int) Config::get('keycloak-web.profile_cache_ttl', 300);
        $this->profileStaleTtl = (int) Config::get('keycloak-web.profile_stale_ttl', 900);
        $this->stateTtl = (int) Config::get('keycloak-web.state_ttl', 600);
        $this->maxStates = (int) Config::get('keycloak-web.max_states', 5);
        $this->verifySignature = (bool) Config::get('keycloak-web.verify_signature', false);
        $this->useUserinfo = (bool) Config::get('keycloak-web.use_userinfo', true);
        $this->leeway = (int) Config::get('keycloak-web.leeway', 60);

        $this->state = $this->generateRandomState();
        $this->httpClient = $client;
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl()
    {
        $url = $this->getOpenIdValue('authorization_endpoint');
        $params = [
            'scope' => $this->scopes,
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = $this->getOpenIdValue('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }

        $params = [
            'client_id' => $this->getClientId()
        ];
        $token = $this->retrieveToken();
        if (! empty($token['id_token'])) {
            $params['post_logout_redirect_uri'] = $this->redirectLogout;
            $params['id_token_hint'] = $token['id_token'];
        }

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the register URL
     *
     * @link https://stackoverflow.com/questions/51514437/keycloak-direct-user-link-registration
     *
     * @return string
     */
    public function getRegisterUrl()
    {
        $url = $this->getLoginUrl();
        return str_replace('/auth?', '/registrations?', $url);
    }
    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            } else {
                $this->logWarning('[Keycloak Service] Authorization code exchange failed.', [
                    'status' => $response->getStatusCode(),
                ]);
            }
        } catch (BadResponseException $e) {
            $this->logWarning('[Keycloak Service] Authorization code exchange failed.', [
                'status' => $e->getResponse() ? $e->getResponse()->getStatusCode() : null,
                'body' => $e->getResponse() ? $this->safeBody($e->getResponse()) : null,
            ]);
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  array $credentials
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        $result = $this->refreshAccessTokenWithStatus($credentials);

        return $result['credentials'];
    }

    /**
     * Refresh the access token keeping the failure context
     *
     * Returns ['credentials' => array, 'network_error' => bool, 'status' => int|null]
     * so the caller can tell a transient network problem apart from a
     * rejected refresh token (invalid_grant).
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshAccessTokenWithStatus($credentials)
    {
        $result = [
            'credentials' => [],
            'network_error' => false,
            'status' => null,
        ];

        if (! is_array($credentials) || empty($credentials['refresh_token'])) {
            return $result;
        }

        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);
            $result['status'] = $response->getStatusCode();

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $result['credentials'] = json_decode($token, true) ?: [];
            } else {
                $this->logWarning('[Keycloak Service] Token refresh rejected.', [
                    'status' => $response->getStatusCode(),
                ]);
            }
        } catch (BadResponseException $e) {
            // Keycloak rejected the refresh token (invalid_grant, 400/401...).
            // This is a real session end, not a network problem.
            $result['status'] = $e->getResponse() ? $e->getResponse()->getStatusCode() : null;

            $this->logWarning('[Keycloak Service] Token refresh rejected.', [
                'status' => $result['status'],
                'body' => $e->getResponse() ? $this->safeBody($e->getResponse()) : null,
            ]);
        } catch (GuzzleException $e) {
            $result['network_error'] = true;
            $this->logException($e);
        }

        return $result;
    }

    /**
     * Invalidate Refresh
     *
     * @param  string $refreshToken
     * @return array
     */
    public function invalidateRefreshToken($refreshToken)
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);
            return $response->getStatusCode() === 204;
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return false;
    }

    /**
     * Get the user profile
     *
     * @param  array $credentials
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $useUserinfo = $this->useUserinfo;

        if (! $useUserinfo && ! $this->verifySignature) {
            // Never trust ID token claims without verifying their signature:
            // fall back to userinfo, which is validated by Keycloak itself.
            $this->logWarning('[Keycloak Service] "use_userinfo = false" requires "verify_signature = true"; falling back to userinfo for safety.');

            $useUserinfo = true;
        }

        $this->lastRefreshNetworkError = false;
        $credentials = $this->refreshTokenIfNeeded($credentials);

        try {
            // Validate JWT Token
            $token = new KeycloakAccessToken($credentials);

            if (empty($token->getAccessToken())) {
                // No token: only degrade when we still hold credentials
                // (transient network problem), never for a forgotten token.
                return $this->retrieveStaleProfile($credentials, 'no access token');
            }

            if ($this->verifySignature) {
                $this->verifyTokenSignatures($token);
            }

            $claims = array(
                'aud' => $this->getClientId(),
                'iss' => $this->getOpenIdValue('issuer'),
            );

            $token->validateIdToken($claims, $this->leeway);

            // Cached profile for this very same access token
            $cached = $this->retrieveCachedProfile($token->getAccessToken());
            if (! empty($cached)) {
                return $cached;
            }

            $user = $useUserinfo
                ? $this->fetchUserProfileFromUserInfo($token)
                : $this->buildProfileFromIdToken($token);

            if (! empty($user)) {
                $this->saveProfileCache($token->getAccessToken(), $user);
            }

            return $user;
        } catch (GuzzleException $e) {
            $this->logException($e);

            // Only degrade on outages (network errors or 5xx). A 4xx means
            // Keycloak is reachable and rejected the token, so the session
            // must end instead of being kept alive with a cached profile.
            if ($this->shouldDegradeOnException($e)) {
                return $this->retrieveStaleProfile($credentials, 'network error');
            }
        } catch (Exception $e) {
            $this->logError('[Keycloak Service] ' . $e->getMessage());

            // The tokens expired AND the refresh failed because of the network:
            // serve the last known profile instead of logging the user out.
            // A plain expired token (or a rejected refresh) must end the session.
            if ($this->lastRefreshNetworkError && strpos($e->getMessage(), 'expired') !== false) {
                return $this->retrieveStaleProfile($credentials, 'expired token during an outage');
            }

            // Discovery endpoint unreachable and not cached
            if (strpos($e->getMessage(), 'It was not possible to load OpenId configuration') !== false) {
                return $this->retrieveStaleProfile($credentials, 'discovery unreachable');
            }
        }

        return [];
    }

    /**
     * Retrieve the profile from the userinfo endpoint
     *
     * @param  KeycloakAccessToken $token
     * @throws GuzzleException
     * @return array
     */
    protected function fetchUserProfileFromUserInfo(KeycloakAccessToken $token)
    {
        $url = $this->getOpenIdValue('userinfo_endpoint');
        $headers = [
            'Authorization' => 'Bearer ' . $token->getAccessToken(),
            'Accept' => 'application/json',
        ];

        $response = $this->httpClient->request('GET', $url, ['headers' => $headers]);

        if ($response->getStatusCode() !== 200) {
            throw new Exception('Was not able to get userinfo (not 200)');
        }

        $user = $response->getBody()->getContents();
        $user = json_decode($user, true) ?: [];

        // Validate retrieved user is owner of token
        if (empty($user['sub']) || ! $token->validateSub($user['sub'])) {
            throw new Exception('Userinfo subject does not match the ID token.');
        }

        return $user;
    }

    /**
     * Build the profile from the ID token claims (no network call)
     *
     * Requires the "email" and "profile" scopes to be requested.
     *
     * @param  KeycloakAccessToken $token
     * @throws Exception
     * @return array
     */
    protected function buildProfileFromIdToken(KeycloakAccessToken $token)
    {
        $claims = $token->parseIdToken();

        if (empty($claims['email'])) {
            throw new Exception('The ID token does not contain an email claim. Request the "email" scope or enable use_userinfo.');
        }

        $givenName = $claims['given_name'] ?? '';
        $familyName = $claims['family_name'] ?? '';

        return [
            'sub' => $claims['sub'] ?? null,
            'email' => $claims['email'],
            'email_verified' => $claims['email_verified'] ?? null,
            'given_name' => $givenName,
            'family_name' => $familyName,
            'name' => $claims['name'] ?? trim($givenName . ' ' . $familyName),
            'preferred_username' => $claims['preferred_username'] ?? null,
        ];
    }

    /**
     * Verify the signature of the ID token (and the access token when present)
     *
     * @param  KeycloakAccessToken $token
     * @throws Exception
     * @return void
     */
    protected function verifyTokenSignatures(KeycloakAccessToken $token)
    {
        $publicKey = Config::get('keycloak-web.realm_public_key');
        $algorithms = (array) Config::get('keycloak-web.signature_algorithms', ['RS256']);

        $token->verifySignature($token->getIdToken(), $publicKey, $algorithms);

        // The access token is validated server side by the userinfo endpoint;
        // verify it locally only when userinfo is disabled.
        if (! $this->useUserinfo && ! empty($token->getAccessToken())) {
            $token->verifySignature($token->getAccessToken(), $publicKey, $algorithms);
        }
    }

    /**
     * Retrieve Token from Session
     *
     * @return array|null
     */
    public function retrieveToken()
    {
        return $this->sessionGet(self::KEYCLOAK_SESSION);
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        $this->sessionPut(self::KEYCLOAK_SESSION, $credentials);

        // The cached profile is not cleared here: it is keyed by the access
        // token hash (re-keyed on refresh) and only removed by forgetToken(),
        // so a token rotation does not lose the outage protection.
        $this->sessionSave();
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        $this->sessionForget(self::KEYCLOAK_SESSION);
        $this->sessionForget(self::KEYCLOAK_SESSION_PROFILE);
        $this->sessionSave();
    }

    /**
     * Validate State from Session
     *
     * Accepts the legacy single state and any of the stored states
     * (multiple tabs / browsers) while they are inside the TTL.
     *
     * @param  string $state
     * @return bool
     */
    public function validateState($state)
    {
        // Reject non scalar input (e.g. ?state[]=x) instead of casting it
        if (! is_string($state) || $state === '') {
            return false;
        }

        // States stored in the list: the TTL is enforced here
        $states = $this->retrieveStates();

        if (isset($states[$state])) {
            if ($this->stateTtl > 0 && (int) $states[$state] < (time() - $this->stateTtl)) {
                return false;
            }

            return true;
        }

        // Legacy single state (sessions started before the upgrade)
        $legacy = $this->sessionGet(self::KEYCLOAK_SESSION_STATE);

        return ! empty($legacy) && hash_equals((string) $legacy, $state);
    }

    /**
     * Save State to Session
     *
     * @return void
     */
    public function saveState()
    {
        $now = time();
        $states = $this->retrieveStates();

        // Purge expired states
        foreach ($states as $key => $issuedAt) {
            if ($this->stateTtl > 0 && (int) $issuedAt < ($now - $this->stateTtl)) {
                unset($states[$key]);
            }
        }

        $states[$this->state] = $now;

        // Keep only the most recent ones (insertion order is chronological,
        // timestamps can be identical when a user opens several tabs at once)
        if ($this->maxStates > 0 && count($states) > $this->maxStates) {
            $states = array_slice($states, -$this->maxStates, null, true);
        }

        $this->sessionPut(self::KEYCLOAK_SESSION_STATES, $states);

        // Legacy single state (backwards compatibility)
        $this->sessionPut(self::KEYCLOAK_SESSION_STATE, $this->state);

        $this->sessionSave();
    }

    /**
     * Remove the used state from the session
     *
     * @param  string $state
     * @return void
     */
    public function consumeState($state)
    {
        $states = $this->retrieveStates();
        unset($states[(string) $state]);

        if (empty($states)) {
            $this->sessionForget(self::KEYCLOAK_SESSION_STATES);
        } else {
            $this->sessionPut(self::KEYCLOAK_SESSION_STATES, $states);
        }

        $legacy = $this->sessionGet(self::KEYCLOAK_SESSION_STATE);
        if (! empty($legacy) && hash_equals((string) $legacy, (string) $state)) {
            $this->sessionForget(self::KEYCLOAK_SESSION_STATE);
        }

        $this->sessionForget(self::KEYCLOAK_SESSION_STATE_FAILURES);
        $this->sessionSave();
    }

    /**
     * Remove State from Session
     *
     * @return void
     */
    public function forgetState()
    {
        $this->sessionForget(self::KEYCLOAK_SESSION_STATE);
        $this->sessionForget(self::KEYCLOAK_SESSION_STATES);
        $this->sessionSave();
    }

    /**
     * Count a failed state validation (loop protection)
     *
     * @return int
     */
    public function registerFailedState()
    {
        $failures = (int) $this->sessionGet(self::KEYCLOAK_SESSION_STATE_FAILURES, 0) + 1;
        $this->sessionPut(self::KEYCLOAK_SESSION_STATE_FAILURES, $failures);
        $this->sessionSave();

        return $failures;
    }

    /**
     * Reset the failed state counter
     *
     * @return void
     */
    public function forgetFailedState()
    {
        $this->sessionForget(self::KEYCLOAK_SESSION_STATE_FAILURES);
    }

    /**
     * Build a URL with params
     *
     * @param  string $url
     * @param  array $params
     * @return string
     */
    public function buildUrl($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?') . '?' . Arr::query($params);
        }

        if (! empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':' . $parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
        $query = [];

        if (! empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url . '?' . Arr::query($query);
    }

    /**
     * Return the client id for requests
     *
     * @return string
     */
    protected function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Return the state for requests
     *
     * @return string
     */
    protected function getState()
    {
        return $this->state;
    }

    /**
     * Return a value from the Open ID Configuration
     *
     * @param  string $key
     * @return string
     */
    protected function getOpenIdValue($key)
    {
        if (! $this->openid) {
            $this->openid = $this->getOpenIdConfiguration();
        }

        return Arr::get($this->openid, $key);
    }

    /**
     * Retrieve OpenId Endpoints
     *
     * @return array
     */
    protected function getOpenIdConfiguration()
    {
        $cacheKey = 'keycloak_web_guard_openid-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        if ($this->cacheOpenid) {
            $configuration = Cache::get($cacheKey, []);

            if (! empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if ($response->getStatusCode() === 200) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);

            throw new Exception('[Keycloak Error] It was not possible to load OpenId configuration: ' . $e->getMessage());
        }

        // Save cache
        if ($this->cacheOpenid) {
            $ttl = Config::get('keycloak-web.openid_cache_ttl');

            if (empty($ttl)) {
                Cache::forever($cacheKey, $configuration);
            } else {
                Cache::put($cacheKey, $configuration, (int) $ttl);
            }
        }

        return $configuration;
    }

    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new KeycloakAccessToken($credentials);
        if (! $token->hasExpired($this->leeway)) {
            return $credentials;
        }

        $result = $this->refreshAccessTokenWithStatus($credentials);

        // Remember if the refresh failed because Keycloak is unreachable:
        // only in that case an expired token may use the cached profile.
        $this->lastRefreshNetworkError = (bool) $result['network_error'];

        if (! empty($result['credentials']['access_token'])) {
            // Keycloak may omit the id_token on refresh responses: keep the
            // previous claims instead of dropping them.
            $previousToken = $credentials['access_token'];
            $credentials = array_merge($credentials, $result['credentials']);

            // Keep the cached profile usable after the token rotation
            $this->rekeyProfileCache($previousToken, $credentials['access_token']);

            $this->saveToken($credentials);

            return $credentials;
        }

        if ($result['network_error']) {
            // Transient failure: keep the credentials so the next request can
            // try again instead of logging the user out.
            $this->logWarning('[Keycloak Service] Token refresh failed because of a network error; keeping the current session.');

            return $credentials;
        }

        // Keycloak rejected the refresh token: the SSO session is over
        $this->forgetToken();

        return [];
    }

    /**
     * Log a GuzzleException
     *
     * Never include the request object: its dump contains the
     * "Authorization: Bearer <access_token>" header, which would leak a live
     * credential into the application log.
     *
     * @param GuzzleException $e
     * @return void
     */
    protected function logException(GuzzleException $e)
    {
        $context = ['message' => $e->getMessage()];

        if (method_exists($e, 'getRequest')) {
            try {
                $context['method'] = $e->getRequest()->getMethod();
                $context['uri'] = (string) $e->getRequest()->getUri();
            } catch (\Throwable $t) {
                // ignore
            }
        }

        if (method_exists($e, 'getResponse') && ! empty($e->getResponse())) {
            $context['status'] = $e->getResponse()->getStatusCode();
            $context['response'] = $this->safeBody($e->getResponse());
        }

        $this->logError('[Keycloak Service] ' . print_r($context, true));
    }

    /**
     * Read a response body without throwing
     *
     * @param  mixed $response
     * @return string
     */
    protected function safeBody($response)
    {
        try {
            if (method_exists($response, 'getBody')) {
                $body = (string) $response->getBody();

                return mb_substr($body, 0, 500);
            }
        } catch (\Throwable $e) {
            // ignore
        }

        return '';
    }

    /**
     * Decide if an exception means Keycloak is unreachable and we may keep the
     * session alive with a cached profile
     *
     * @param  GuzzleException $e
     * @return bool
     */
    protected function shouldDegradeOnException(GuzzleException $e)
    {
        if ($e instanceof ConnectException || $e instanceof ServerException) {
            return true;
        }

        // 4xx (ClientException): the token was rejected, do not degrade
        if ($e instanceof BadResponseException) {
            return false;
        }

        // No HTTP response at all (DNS, socket, TLS...)
        if (method_exists($e, 'getResponse')) {
            return empty($e->getResponse());
        }

        return false;
    }

    /**
     * Log a warning without breaking when the logger is not available
     *
     * @param  string $message
     * @param  array  $context
     * @return void
     */
    protected function logWarning($message, array $context = [])
    {
        try {
            Log::warning($message, $context);
        } catch (\Throwable $e) {
            // ignore
        }
    }

    /**
     * Log an error without breaking when the logger is not available
     *
     * @param  string $message
     * @return void
     */
    protected function logError($message)
    {
        try {
            Log::error($message);
        } catch (\Throwable $e) {
            // ignore
        }
    }

    /**
     * Retrieve the stored authorization states
     *
     * @return array
     */
    protected function retrieveStates()
    {
        $states = $this->sessionGet(self::KEYCLOAK_SESSION_STATES);

        return is_array($states) ? $states : [];
    }

    /**
     * Save the user profile in the session
     *
     * @param  string $accessToken
     * @param  array  $profile
     * @return void
     */
    protected function saveProfileCache($accessToken, array $profile)
    {
        if ($this->profileCacheTtl <= 0) {
            return;
        }

        $this->sessionPut(self::KEYCLOAK_SESSION_PROFILE, [
            'hash' => sha1($accessToken),
            'profile' => $profile,
            'expires_at' => time() + $this->profileCacheTtl,
        ]);
    }

    /**
     * Move the cached profile to the new access token after a rotation
     *
     * @param  string $oldAccessToken
     * @param  string $newAccessToken
     * @return void
     */
    protected function rekeyProfileCache($oldAccessToken, $newAccessToken)
    {
        if ($this->profileCacheTtl <= 0
            || empty($oldAccessToken)
            || empty($newAccessToken)
            || $oldAccessToken === $newAccessToken) {
            return;
        }

        $cache = $this->sessionGet(self::KEYCLOAK_SESSION_PROFILE);

        if (empty($cache['profile']) || empty($cache['hash'])) {
            return;
        }

        if (! hash_equals((string) $cache['hash'], sha1($oldAccessToken))) {
            return;
        }

        // Same user, same expiration: only the token fingerprint changes
        $cache['hash'] = sha1($newAccessToken);

        $this->sessionPut(self::KEYCLOAK_SESSION_PROFILE, $cache);
    }

    /**
     * Retrieve a fresh cached profile for the given access token
     *
     * @param  string $accessToken
     * @return array
     */
    protected function retrieveCachedProfile($accessToken)
    {
        if ($this->profileCacheTtl <= 0) {
            return [];
        }

        $cache = $this->sessionGet(self::KEYCLOAK_SESSION_PROFILE);

        if (empty($cache['profile']) || empty($cache['hash'])) {
            return [];
        }

        if (! hash_equals((string) $cache['hash'], sha1($accessToken))) {
            return [];
        }

        if (time() > (int) ($cache['expires_at'] ?? 0)) {
            return [];
        }

        return (array) $cache['profile'];
    }

    /**
     * Retrieve a cached profile to survive a Keycloak outage
     *
     * Only used when the session still holds credentials (network problem),
     * never when the token was intentionally forgotten.
     *
     * @param  array  $credentials
     * @param  string $reason
     * @return array
     */
    protected function retrieveStaleProfile($credentials, $reason)
    {
        if (! is_array($credentials) || empty($credentials['access_token'])) {
            return [];
        }

        $cache = $this->sessionGet(self::KEYCLOAK_SESSION_PROFILE);

        if (empty($cache['profile']) || empty($cache['hash'])) {
            return [];
        }

        if (! hash_equals((string) $cache['hash'], sha1($credentials['access_token']))) {
            return [];
        }

        $expiresAt = (int) ($cache['expires_at'] ?? 0) + $this->profileStaleTtl;

        if (time() > $expiresAt) {
            return [];
        }

        $this->logWarning('[Keycloak Service] Using the cached user profile (' . $reason . ').');

        return (array) $cache['profile'];
    }

    /**
     * Session getter that never blows up outside a HTTP context
     *
     * @param  string $key
     * @param  mixed  $default
     * @return mixed
     */
    protected function sessionGet($key, $default = null)
    {
        try {
            return session()->get($key, $default);
        } catch (\Throwable $e) {
            return $default;
        }
    }

    /**
     * Session putter that never blows up outside a HTTP context
     *
     * @param  string $key
     * @param  mixed  $value
     * @return void
     */
    protected function sessionPut($key, $value)
    {
        try {
            session()->put($key, $value);
        } catch (\Throwable $e) {
            // ignore
        }
    }

    /**
     * Session forgetter that never blows up outside a HTTP context
     *
     * @param  string $key
     * @return void
     */
    protected function sessionForget($key)
    {
        try {
            session()->forget($key);
        } catch (\Throwable $e) {
            // ignore
        }
    }

    /**
     * Persist the session without blowing up outside a HTTP context
     *
     * @return void
     */
    protected function sessionSave()
    {
        try {
            session()->save();
        } catch (\Throwable $e) {
            // A failing session handler silently breaks the whole SSO flow, so
            // leave a trace (once per request) instead of swallowing it.
            if (! $this->sessionFailureLogged) {
                $this->sessionFailureLogged = true;

                $this->logWarning('[Keycloak Service] The session could not be persisted.', [
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Return a random state parameter for authorization
     *
     * @return string
     */
    protected function generateRandomState()
    {
        return bin2hex(random_bytes(16));
    }
}
