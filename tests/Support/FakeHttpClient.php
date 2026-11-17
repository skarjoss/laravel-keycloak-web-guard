<?php

namespace Vizir\KeycloakWebGuard\Tests\Support;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Cliente HTTP falso: ejecuta el callback recibido en cada request.
 */
class FakeHttpClient implements ClientInterface
{
    /** @var callable */
    private $behaviour;

    public function __construct(callable $behaviour)
    {
        $this->behaviour = $behaviour;
    }

    public function send(RequestInterface $request, array $options = []): ResponseInterface
    {
        return ($this->behaviour)($request->getMethod(), (string) $request->getUri());
    }

    public function sendAsync(RequestInterface $request, array $options = []): PromiseInterface
    {
        throw new \LogicException('sendAsync() is not used in the tests.');
    }

    public function request(string $method, $uri = '', array $options = []): ResponseInterface
    {
        return ($this->behaviour)($method, (string) $uri);
    }

    public function requestAsync(string $method, $uri = '', array $options = []): PromiseInterface
    {
        throw new \LogicException('requestAsync() is not used in the tests.');
    }

    public function getConfig(?string $option = null)
    {
        return null;
    }
}
