<?php

namespace Vizir\KeycloakWebGuard\Tests\Support;

use GuzzleHttp\ClientInterface;
use ReflectionClass;
use Vizir\KeycloakWebGuard\Services\KeycloakService;

/**
 * KeycloakService con sesión en memoria y endpoints falsos, para poder probar
 * la lógica sin arrancar una aplicación Laravel.
 */
class InMemoryKeycloakService extends KeycloakService
{
    /** @var array */
    public $store = [];

    /** @var array|null */
    public $savedToken;

    /** @var bool */
    public $forgotTokenCalled = false;

    /** @var array */
    private $endpoints = [
        'issuer' => 'https://sso.test/realms/bgr_oidc1',
        'token_endpoint' => 'https://sso.test/token',
        'userinfo_endpoint' => 'https://sso.test/userinfo',
        'authorization_endpoint' => 'https://sso.test/auth',
        'end_session_endpoint' => 'https://sso.test/logout',
    ];

    protected function sessionGet($key, $default = null)
    {
        return array_key_exists($key, $this->store) ? $this->store[$key] : $default;
    }

    protected function sessionPut($key, $value)
    {
        $this->store[$key] = $value;
    }

    protected function sessionForget($key)
    {
        unset($this->store[$key]);
    }

    protected function sessionSave()
    {
        // no-op
    }

    protected function getOpenIdValue($key)
    {
        return $this->endpoints[$key] ?? null;
    }

    public function saveToken($credentials)
    {
        $this->savedToken = $credentials;
    }

    public function forgetToken()
    {
        $this->forgotTokenCalled = true;
        $this->savedToken = null;
        $this->store = [];
    }

    /**
     * Crea una instancia sin llamar al constructor (que requiere Laravel).
     */
    public static function make(array $props = []): self
    {
        $ref = new ReflectionClass(self::class);
        $service = $ref->newInstanceWithoutConstructor();

        $defaults = [
            'httpClient' => null,
            'leeway' => 0,
            'clientId' => 'voc-bgr-prod',
            'clientSecret' => 'secret',
            'callbackUrl' => 'https://app.test/callback-sso',
            'verifySignature' => false,
            'useUserinfo' => true,
            'profileCacheTtl' => 300,
            'profileStaleTtl' => 900,
            'stateTtl' => 600,
            'maxStates' => 5,
            'scopes' => 'openid',
            'state' => 'initial-state',
            'sessionFailureLogged' => false,
        ];

        foreach (array_merge($defaults, $props) as $name => $value) {
            if (! $ref->hasProperty($name)) {
                continue;
            }

            $property = $ref->getProperty($name);
            $property->setAccessible(true);
            $property->setValue($service, $value);
        }

        return $service;
    }

    // --- Accesos para las aserciones ---------------------------------------

    public function forceState(string $state): void
    {
        $this->state = $state;
    }

    public function readStore(string $key, $default = null)
    {
        return $this->sessionGet($key, $default);
    }

    public function writeStore(string $key, $value): void
    {
        $this->sessionPut($key, $value);
    }

    public function cacheProfile(string $accessToken, array $profile): void
    {
        $this->saveProfileCache($accessToken, $profile);
    }

    public function cachedProfile(string $accessToken): array
    {
        return $this->retrieveCachedProfile($accessToken);
    }

    public function staleProfile(array $credentials): array
    {
        return $this->retrieveStaleProfile($credentials, 'test');
    }

    public function profile(array $credentials): array
    {
        return $this->getUserProfile($credentials);
    }

    public function refresh(array $credentials): array
    {
        return $this->refreshTokenIfNeeded($credentials);
    }

    public function withClient(ClientInterface $client): self
    {
        $this->httpClient = $client;

        return $this;
    }
}
