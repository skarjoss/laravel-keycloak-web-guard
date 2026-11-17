<?php

namespace Vizir\KeycloakWebGuard\Tests\Unit;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Vizir\KeycloakWebGuard\Services\KeycloakService;
use Vizir\KeycloakWebGuard\Tests\Support\FakeHttpClient;
use Vizir\KeycloakWebGuard\Tests\Support\InMemoryKeycloakService;
use Vizir\KeycloakWebGuard\Tests\Support\JwtFactory;

class CollectingLogger extends AbstractLogger
{
    public $messages = [];

    public function log($level, $message, array $context = []): void
    {
        $this->messages[] = ['level' => $level, 'message' => (string) $message];
    }

    public function contains(string $needle): bool
    {
        foreach ($this->messages as $message) {
            if (strpos($message['message'], $needle) !== false) {
                return true;
            }
        }

        return false;
    }
}

class SecurityConfigTest extends TestCase
{
    private $app;

    /** @var CollectingLogger */
    private $logger;

    protected function setUp(): void
    {
        $this->app = new Container();
        Container::setInstance($this->app);

        $this->logger = new CollectingLogger();

        $this->app->instance('config', new Repository([
            'keycloak-web' => [
                'base_url' => 'https://sso.test',
                'realm' => 'bgr_oidc1',
                'realm_public_key' => JwtFactory::keys()[1],
                'signature_algorithms' => ['RS256'],
                'cache_openid' => false,
                'guzzle_options' => [],
                'http' => [],
            ],
        ]));

        $this->app->instance('log', $this->logger);

        Facade::setFacadeApplication($this->app);
    }

    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Container::setInstance(null);
    }

    private function credentials(string $jwt): array
    {
        return ['access_token' => $jwt, 'refresh_token' => 'r1', 'id_token' => $jwt];
    }

    public function test_disabling_userinfo_without_signature_falls_back_to_userinfo(): void
    {
        $jwt = JwtFactory::tokenExpiringIn(300);

        $service = InMemoryKeycloakService::make([
            'useUserinfo' => false,
            'verifySignature' => false,
            'httpClient' => new FakeHttpClient(function () {
                return new Response(200, [], json_encode([
                    'sub' => '8c1f-user',
                    'email' => 'agente@bgr.com.ec',
                    'given_name' => 'Ana',
                    'family_name' => 'Pérez',
                ]));
            }),
        ]);

        $profile = $service->profile($this->credentials($jwt));

        $this->assertSame('agente@bgr.com.ec', $profile['email'] ?? null);
        $this->assertTrue($this->logger->contains('falling back to userinfo'));
    }

    public function test_disabling_userinfo_with_a_valid_signature_uses_no_http_calls(): void
    {
        $jwt = JwtFactory::tokenExpiringIn(300);

        $service = InMemoryKeycloakService::make([
            'useUserinfo' => false,
            'verifySignature' => true,
            'httpClient' => new FakeHttpClient(function () {
                throw new \LogicException('No HTTP call should be made.');
            }),
        ]);

        $profile = $service->profile($this->credentials($jwt));

        $this->assertSame('agente@bgr.com.ec', $profile['email'] ?? null);
        $this->assertSame('Ana', $profile['given_name'] ?? null);
        $this->assertSame('Pérez', $profile['family_name'] ?? null);
    }

    public function test_a_tampered_id_token_is_rejected_when_signature_is_enabled(): void
    {
        $jwt = JwtFactory::tokenExpiringIn(300);
        $parts = explode('.', $jwt);
        $tampered = $parts[0] . '.' . JwtFactory::base64Url(json_encode(JwtFactory::claims([
            'email' => 'attacker@evil.com',
        ]))) . '.' . $parts[2];

        $service = InMemoryKeycloakService::make([
            'verifySignature' => true,
            'httpClient' => new FakeHttpClient(function () {
                throw new \LogicException('No HTTP call should be made.');
            }),
        ]);

        $this->assertSame([], $service->profile($this->credentials($tampered)));
        $this->assertTrue($this->logger->contains('Token signature is invalid.'));
    }

    public function test_the_exception_log_never_contains_the_bearer_token(): void
    {
        $service = InMemoryKeycloakService::make();

        $ref = new \ReflectionClass(KeycloakService::class);
        $method = $ref->getMethod('logException');
        $method->setAccessible(true);

        $request = new Request('GET', 'https://sso.test/userinfo', [
            'Authorization' => 'Bearer super-secret-token',
        ]);

        $method->invoke($service, new ClientException(
            '401 Unauthorized',
            $request,
            new Response(401, [], '{"error":"invalid_token"}')
        ));

        $this->assertFalse($this->logger->contains('Bearer'));
        $this->assertFalse($this->logger->contains('super-secret-token'));
        $this->assertTrue($this->logger->contains('https://sso.test/userinfo'));
    }
}
