<?php

namespace Vizir\KeycloakWebGuard\Tests\Unit;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Vizir\KeycloakWebGuard\Services\KeycloakService;
use Vizir\KeycloakWebGuard\Tests\Support\FakeHttpClient;
use Vizir\KeycloakWebGuard\Tests\Support\InMemoryKeycloakService;
use Vizir\KeycloakWebGuard\Tests\Support\JwtFactory;

/**
 * La degradación a perfil cacheado solo debe ocurrir con una caída real de
 * Keycloak (red o 5xx). Un 4xx significa que el token fue rechazado.
 */
class DegradationTest extends TestCase
{
    private const PROFILE = ['sub' => 'u1', 'email' => 'agente@bgr.com.ec'];

    private function serviceWithStaleCache(callable $behaviour): InMemoryKeycloakService
    {
        $accessToken = JwtFactory::tokenExpiringIn(300);

        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient($behaviour),
        ]);

        $service->cacheProfile($accessToken, self::PROFILE);

        // Caché vencida: solo se usará si hay degradación
        $cache = $service->readStore(KeycloakService::KEYCLOAK_SESSION_PROFILE);
        $cache['expires_at'] = time() - 1;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_PROFILE, $cache);

        return $service;
    }

    private function credentials(): array
    {
        return [
            'access_token' => JwtFactory::tokenExpiringIn(300),
            'refresh_token' => 'r1',
            'id_token' => JwtFactory::tokenExpiringIn(300),
        ];
    }

    public function test_a_revoked_token_is_not_kept_alive_by_the_cache(): void
    {
        $service = $this->serviceWithStaleCache(function () {
            throw new ClientException('401 Unauthorized', new Request('GET', 'https://sso.test/userinfo'), new Response(401));
        });

        $this->assertSame([], $service->profile($this->credentials()));
    }

    public function test_a_forbidden_response_is_not_kept_alive_by_the_cache(): void
    {
        $service = $this->serviceWithStaleCache(function () {
            throw new ClientException('403 Forbidden', new Request('GET', 'https://sso.test/userinfo'), new Response(403));
        });

        $this->assertSame([], $service->profile($this->credentials()));
    }

    public function test_a_server_error_degrades_to_the_cached_profile(): void
    {
        $service = $this->serviceWithStaleCache(function () {
            throw new ServerException('500 Internal Server Error', new Request('GET', 'https://sso.test/userinfo'), new Response(500));
        });

        $this->assertSame(self::PROFILE, $service->profile($this->credentials()));
    }

    public function test_a_network_error_degrades_to_the_cached_profile(): void
    {
        $service = $this->serviceWithStaleCache(function () {
            throw new ConnectException('cURL error 28: timed out', new Request('GET', 'https://sso.test/userinfo'));
        });

        $this->assertSame(self::PROFILE, $service->profile($this->credentials()));
    }

    public function test_expired_tokens_during_an_outage_keep_the_session(): void
    {
        $accessToken = JwtFactory::tokenExpiringIn(-120);

        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function () {
                throw new ConnectException('cURL error 28: timed out', new Request('POST', 'https://sso.test/token'));
            }),
        ]);

        $service->cacheProfile($accessToken, self::PROFILE);
        $cache = $service->readStore(KeycloakService::KEYCLOAK_SESSION_PROFILE);
        $cache['expires_at'] = time() - 10;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_PROFILE, $cache);

        $profile = $service->profile([
            'access_token' => $accessToken,
            'refresh_token' => 'r1',
            'id_token' => JwtFactory::tokenExpiringIn(-120),
        ]);

        $this->assertSame(self::PROFILE, $profile);
        $this->assertFalse($service->forgotTokenCalled);
    }

    public function test_an_expired_refresh_token_still_ends_the_session(): void
    {
        $accessToken = JwtFactory::tokenExpiringIn(-120);

        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function () {
                throw new ClientException(
                    '400 Bad Request',
                    new Request('POST', 'https://sso.test/token'),
                    new Response(400, [], '{"error":"invalid_grant"}')
                );
            }),
        ]);

        $service->cacheProfile($accessToken, self::PROFILE);

        $profile = $service->profile([
            'access_token' => $accessToken,
            'refresh_token' => 'r1',
            'id_token' => JwtFactory::tokenExpiringIn(-120),
        ]);

        $this->assertSame([], $profile);
        $this->assertTrue($service->forgotTokenCalled);
    }

    public function test_an_expired_token_without_refresh_capability_ends_the_session(): void
    {
        $accessToken = JwtFactory::tokenExpiringIn(-120);

        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function () {
                throw new \LogicException('No HTTP call should be made.');
            }),
        ]);

        $service->cacheProfile($accessToken, self::PROFILE);

        $cache = $service->readStore(KeycloakService::KEYCLOAK_SESSION_PROFILE);
        $cache['expires_at'] = time() - 1;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_PROFILE, $cache);

        // Sin refresh token y sin caída de red: el token expiró de verdad
        $profile = $service->profile([
            'access_token' => $accessToken,
            'refresh_token' => '',
            'id_token' => $accessToken,
        ]);

        $this->assertSame([], $profile);
    }

    public function test_the_cached_profile_survives_a_token_rotation(): void
    {
        $expiredAccess = JwtFactory::tokenExpiringIn(-60);
        $newAccess = JwtFactory::tokenExpiringIn(300);

        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function ($method, $uri) use ($newAccess) {
                if (strpos($uri, 'token') !== false) {
                    return new Response(200, [], json_encode([
                        'access_token' => $newAccess,
                        'refresh_token' => 'r2',
                        'expires_in' => 300,
                    ]));
                }

                throw new ServerException('500 Internal Server Error', new Request('GET', $uri), new Response(500));
            }),
        ]);

        $service->cacheProfile($expiredAccess, self::PROFILE);

        $cache = $service->readStore(KeycloakService::KEYCLOAK_SESSION_PROFILE);
        $cache['expires_at'] = time() - 1;
        $service->writeStore(KeycloakService::KEYCLOAK_SESSION_PROFILE, $cache);

        $profile = $service->profile([
            'access_token' => $expiredAccess,
            'refresh_token' => 'r1',
            'id_token' => JwtFactory::tokenExpiringIn(300),
        ]);

        $this->assertSame(self::PROFILE, $profile);
        $this->assertSame($newAccess, $service->savedToken['access_token']);
    }
}
