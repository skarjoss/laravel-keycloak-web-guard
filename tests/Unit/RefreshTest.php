<?php

namespace Vizir\KeycloakWebGuard\Tests\Unit;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Vizir\KeycloakWebGuard\Tests\Support\FakeHttpClient;
use Vizir\KeycloakWebGuard\Tests\Support\InMemoryKeycloakService;
use Vizir\KeycloakWebGuard\Tests\Support\JwtFactory;

class RefreshTest extends TestCase
{
    private function expiredCredentials(): array
    {
        return [
            'access_token' => JwtFactory::tokenExpiringIn(-60),
            'refresh_token' => 'refresh-abc',
            'id_token' => JwtFactory::tokenExpiringIn(300),
        ];
    }

    public function test_a_network_error_does_not_destroy_the_session(): void
    {
        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function () {
                throw new ConnectException(
                    'cURL error 28: Connection timed out after 5000 milliseconds',
                    new Request('POST', 'https://sso.test/token')
                );
            }),
        ]);

        $credentials = $this->expiredCredentials();
        $result = $service->refresh($credentials);

        $this->assertSame($credentials['access_token'], $result['access_token']);
        $this->assertFalse($service->forgotTokenCalled);
    }

    public function test_a_rejected_refresh_token_ends_the_session(): void
    {
        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function () {
                throw new ClientException(
                    '400 Bad Request',
                    new Request('POST', 'https://sso.test/token'),
                    new Response(400, [], '{"error":"invalid_grant"}')
                );
            }),
        ]);

        $this->assertSame([], $service->refresh($this->expiredCredentials()));
        $this->assertTrue($service->forgotTokenCalled);
    }

    public function test_a_successful_refresh_keeps_the_previous_id_token_when_missing(): void
    {
        $newAccess = JwtFactory::tokenExpiringIn(300);
        $oldIdToken = JwtFactory::tokenExpiringIn(300, ['sub' => 'u1']);

        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function () use ($newAccess) {
                return new Response(200, [], json_encode([
                    'access_token' => $newAccess,
                    'refresh_token' => 'refresh-new',
                    'expires_in' => 300,
                ]));
            }),
        ]);

        $result = $service->refresh([
            'access_token' => JwtFactory::tokenExpiringIn(-60),
            'refresh_token' => 'refresh-abc',
            'id_token' => $oldIdToken,
        ]);

        $this->assertSame($newAccess, $result['access_token']);
        $this->assertSame($oldIdToken, $result['id_token']);
        $this->assertSame($newAccess, $service->savedToken['access_token']);
        $this->assertFalse($service->forgotTokenCalled);
    }

    public function test_a_valid_token_is_not_refreshed(): void
    {
        $credentials = [
            'access_token' => JwtFactory::tokenExpiringIn(600),
            'refresh_token' => 'r',
            'id_token' => JwtFactory::tokenExpiringIn(600),
        ];

        $service = InMemoryKeycloakService::make([
            'httpClient' => new FakeHttpClient(function () {
                throw new \LogicException('It should not refresh.');
            }),
        ]);

        $this->assertSame($credentials, $service->refresh($credentials));
    }

    public function test_the_leeway_refreshes_before_expiration(): void
    {
        $service = InMemoryKeycloakService::make([
            'leeway' => 120,
            'httpClient' => new FakeHttpClient(function () {
                throw new ConnectException('cURL error 28: timeout', new Request('POST', 'https://sso.test/token'));
            }),
        ]);

        $result = $service->refresh([
            'access_token' => JwtFactory::tokenExpiringIn(60),
            'refresh_token' => 'r',
            'id_token' => JwtFactory::tokenExpiringIn(60),
        ]);

        $this->assertArrayHasKey('access_token', $result);
        $this->assertFalse($service->forgotTokenCalled);
    }
}
