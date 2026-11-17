<?php

namespace Vizir\KeycloakWebGuard\Tests\Unit;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Vizir\KeycloakWebGuard\KeycloakWebGuardServiceProvider;

class TestableServiceProvider extends KeycloakWebGuardServiceProvider
{
    public function buildClient()
    {
        return $this->buildHttpClient();
    }

    public function isTransient($exception)
    {
        return $this->isTransientException($exception);
    }

    public function makeStack($handler, $retries, $delayMs)
    {
        return $this->buildHandlerStack($handler, $retries, $delayMs);
    }
}

class HttpClientOptionsTest extends TestCase
{
    private $app;

    protected function setUp(): void
    {
        $this->app = new Container();
        Container::setInstance($this->app);

        $this->app->instance('config', new Repository([
            'keycloak-web' => [
                'base_url' => 'https://sso.test',
                'realm' => 'bgr_oidc1',
                'cache_openid' => false,
                'guzzle_options' => [],
                'http' => [],
            ],
        ]));

        Facade::setFacadeApplication($this->app);
    }

    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Container::setInstance(null);
    }

    private function provider(): TestableServiceProvider
    {
        return (new ReflectionClass(TestableServiceProvider::class))->newInstanceWithoutConstructor();
    }

    public function test_safe_defaults_are_applied(): void
    {
        $client = $this->provider()->buildClient();

        $this->assertSame(5, $client->getConfig('timeout'));
        $this->assertSame(3, $client->getConfig('connect_timeout'));
        $this->assertInstanceOf(HandlerStack::class, $client->getConfig('handler'));
    }

    public function test_legacy_guzzle_options_win(): void
    {
        $this->app['config']->set('keycloak-web.guzzle_options', ['timeout' => 12, 'verify' => false]);

        $client = $this->provider()->buildClient();

        $this->assertSame(12, $client->getConfig('timeout'));
        $this->assertFalse($client->getConfig('verify'));
    }

    public function test_http_block_can_override_the_defaults(): void
    {
        $this->app['config']->set('keycloak-web.http', [
            'timeout' => 8,
            'connect_timeout' => 2,
            'retries' => 0,
        ]);

        $client = $this->provider()->buildClient();
        $stack = $client->getConfig('handler');

        $this->assertSame(8, $client->getConfig('timeout'));
        $this->assertSame(2, $client->getConfig('connect_timeout'));
        $this->assertFalse($this->retryMiddlewareIsRegistered($stack));
    }

    public function test_the_retry_middleware_is_registered_by_default(): void
    {
        $stack = $this->provider()->buildClient()->getConfig('handler');

        $this->assertTrue($this->retryMiddlewareIsRegistered($stack));
    }

    /**
     * Guzzle keeps the middleware name as an array key (<= 7.14) or as the
     * second element of a pair (>= 7.15).
     */
    private function retryMiddlewareIsRegistered(HandlerStack $stack): bool
    {
        $property = (new ReflectionClass(HandlerStack::class))->getProperty('stack');
        $property->setAccessible(true);

        foreach ($property->getValue($stack) as $key => $entry) {
            if ($key === 'keycloak_retry') {
                return true;
            }

            if (is_array($entry) && ($entry[1] ?? null) === 'keycloak_retry') {
                return true;
            }
        }

        return false;
    }

    public function test_only_transient_errors_are_retried(): void
    {
        $provider = $this->provider();
        $get = new Request('GET', 'https://sso.test/userinfo');

        $this->assertTrue($provider->isTransient(new ConnectException('cURL error 28: timed out', $get)));
        $this->assertTrue($provider->isTransient(new ConnectException('cURL error 35: reset by peer', $get)));
        $this->assertTrue($provider->isTransient(new ServerException('500', $get, new Response(500))));
        $this->assertFalse($provider->isTransient(new ClientException('400', $get, new Response(400))));
        $this->assertFalse($provider->isTransient(null));
    }
}
