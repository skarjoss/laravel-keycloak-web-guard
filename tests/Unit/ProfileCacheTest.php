<?php

namespace Vizir\KeycloakWebGuard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vizir\KeycloakWebGuard\Services\KeycloakService;
use Vizir\KeycloakWebGuard\Tests\Support\InMemoryKeycloakService;

class ProfileCacheTest extends TestCase
{
    private const PROFILE = [
        'sub' => 'u1',
        'email' => 'agente@bgr.com.ec',
        'given_name' => 'Ana',
        'family_name' => 'Pérez',
    ];

    public function test_a_fresh_cache_is_returned_for_the_same_token(): void
    {
        $service = InMemoryKeycloakService::make();
        $service->cacheProfile('token-1', self::PROFILE);

        $this->assertSame(self::PROFILE, $service->cachedProfile('token-1'));
        $this->assertSame([], $service->cachedProfile('token-2'));
    }

    public function test_an_expired_cache_is_not_fresh_but_can_be_used_as_stale(): void
    {
        $service = InMemoryKeycloakService::make();
        $service->cacheProfile('token-1', self::PROFILE);

        $cache = $service->readStore(KeycloakService::KEYCLOAK_SESSION_PROFILE);
        $cache['expires_at'] = time() - 1;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_PROFILE, $cache);

        $this->assertSame([], $service->cachedProfile('token-1'));
        $this->assertSame(self::PROFILE, $service->staleProfile(['access_token' => 'token-1']));
    }

    public function test_stale_profile_requires_matching_credentials(): void
    {
        $service = InMemoryKeycloakService::make();
        $service->cacheProfile('token-1', self::PROFILE);

        $cache = $service->readStore(KeycloakService::KEYCLOAK_SESSION_PROFILE);
        $cache['expires_at'] = time() - 1;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_PROFILE, $cache);

        $this->assertSame([], $service->staleProfile([]));
        $this->assertSame([], $service->staleProfile(['access_token' => 'other-token']));
    }

    public function test_stale_profile_expires_after_the_grace_window(): void
    {
        $service = InMemoryKeycloakService::make(['profileCacheTtl' => 300, 'profileStaleTtl' => 60]);
        $service->cacheProfile('token-1', self::PROFILE);

        $cache = $service->readStore(KeycloakService::KEYCLOAK_SESSION_PROFILE);
        $cache['expires_at'] = time() - 120;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_PROFILE, $cache);

        $this->assertSame([], $service->staleProfile(['access_token' => 'token-1']));
    }

    public function test_caching_can_be_disabled(): void
    {
        $service = InMemoryKeycloakService::make(['profileCacheTtl' => 0]);
        $service->cacheProfile('token-1', self::PROFILE);

        $this->assertSame([], $service->cachedProfile('token-1'));
    }
}
