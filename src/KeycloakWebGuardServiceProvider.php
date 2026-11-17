<?php

namespace Vizir\KeycloakWebGuard;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Vizir\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;
use Vizir\KeycloakWebGuard\Auth\KeycloakWebUserProvider;
use Vizir\KeycloakWebGuard\Middleware\KeycloakAuthenticated;
use Vizir\KeycloakWebGuard\Middleware\KeycloakCan;
use Vizir\KeycloakWebGuard\Middleware\KeycloakCanOne;
use Vizir\KeycloakWebGuard\Models\KeycloakUser;
use Vizir\KeycloakWebGuard\Services\KeycloakService;

class KeycloakWebGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Configuration
        $config = __DIR__ . '/../config/keycloak-web.php';

        $this->publishes([$config => config_path('keycloak-web.php')], 'config');
        $this->mergeConfigFrom($config, 'keycloak-web');

        // User Provider
        Auth::provider('keycloak-users', function($app, array $config) {
            return new KeycloakWebUserProvider($config['model']);
        });

        // Gate
        Gate::define('keycloak-web', function ($user, $roles, $resource = '') {
            return $user->hasRole($roles, $resource) ?: null;
        });
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        // Keycloak Web Guard
        Auth::extend('keycloak-web', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new KeycloakWebGuard($provider, $app->request);
        });

        // Facades
        $this->app->bind('keycloak-web', function($app) {
            return $app->make(KeycloakService::class);
        });

        // Routes
        $this->registerRoutes();

        // Middleware Group
        $this->app['router']->middlewareGroup('keycloak-web', [
            StartSession::class,
            KeycloakAuthenticated::class,
        ]);

        // Add Middleware "keycloak-web-can"
        $this->app['router']->aliasMiddleware('keycloak-web-can', KeycloakCan::class);

        // Add Middleware "keycloak-web-can-one
        $this->app['router']->aliasMiddleware('keycloak-web-can-one', KeycloakCanOne::class);

        // Bind for client data
        $this->app->when(KeycloakService::class)->needs(ClientInterface::class)->give(function() {
            return $this->buildHttpClient();
        });
    }

    /**
     * Build the HTTP client used to talk to Keycloak
     *
     * The default client has no timeout at all, so a single hung connection to
     * the identity provider could block a PHP worker until the process is
     * killed. Safe defaults (timeout + connect_timeout + retries) are applied
     * here and can be overridden with "keycloak-web.http" or the legacy
     * "keycloak-web.guzzle_options".
     *
     * @return ClientInterface
     */
    protected function buildHttpClient()
    {
        $options = array_merge(
            [
                'timeout' => 5,
                'connect_timeout' => 3,
            ],
            (array) Config::get('keycloak-web.http', []),
            (array) Config::get('keycloak-web.guzzle_options', [])
        );

        $retries = (int) ($options['retries'] ?? 2);
        $retryDelayMs = (int) ($options['retry_delay_ms'] ?? 200);

        unset($options['retries'], $options['retry_delay_ms']);

        if ($retries > 0) {
            $options['handler'] = $this->buildHandlerStack(
                $options['handler'] ?? null,
                $retries,
                $retryDelayMs
            );
        }

        return new Client($options);
    }

    /**
     * Build a handler stack with a conservative retry policy
     *
     * Only GET requests are retried: POST requests to the token endpoint carry
     * single use authorization codes or rotating refresh tokens, so replaying
     * them can invalidate the user session.
     *
     * @param  mixed $handler
     * @param  int   $retries
     * @param  int   $retryDelayMs
     * @return HandlerStack
     */
    protected function buildHandlerStack($handler, $retries, $retryDelayMs)
    {
        $stack = $handler instanceof HandlerStack
            ? $handler
            : HandlerStack::create($handler ?: null);

        $stack->push(Middleware::retry(
            function ($retry, $request = null, $response = null, $exception = null) use ($retries) {
                if ($retry >= $retries) {
                    return false;
                }

                if (! $request || strtoupper($request->getMethod()) !== 'GET') {
                    return false;
                }

                if ($response) {
                    // Retry server side failures only (GET requests)
                    return $response->getStatusCode() >= 500;
                }

                return $this->isTransientException($exception);
            },
            function ($retry) use ($retryDelayMs) {
                return $retryDelayMs * 1000 * $retry;
            }
        ), 'keycloak_retry');

        return $stack;
    }

    /**
     * Determine if an exception is a transient network problem
     *
     * @param  mixed $exception
     * @return bool
     */
    protected function isTransientException($exception)
    {
        if (empty($exception)) {
            return false;
        }

        if ($exception instanceof ConnectException) {
            return true;
        }

        if ($exception instanceof ServerException) {
            return true;
        }

        if ($exception instanceof RequestException && method_exists($exception, 'getHandlerContext')) {
            try {
                $context = $exception->getHandlerContext();
                $errno = (int) ($context['errno'] ?? 0);

                if (in_array($errno, [6, 7, 28, 35, 52, 55, 56], true)) {
                    return true;
                }
            } catch (\Throwable $e) {
                // ignore and fall back to the message check
            }
        }

        return (bool) preg_match('/cURL error (6|7|28|35|52|55|56)\b/', (string) $exception->getMessage());
    }

    /**
     * Register the authentication routes for keycloak.
     *
     * @return void
     */
    private function registerRoutes()
    {
        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'register' => 'register',
            'callback' => 'callback',
        ];

        $routes = Config::get('keycloak-web.routes', []);
        $routes = array_merge($defaults, $routes);

        // Register Routes
        $router = $this->app->make('router');

        if (! empty($routes['login'])) {
            $router->middleware('web')->get($routes['login'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@login')->name('keycloak.login');
        }

        if (! empty($routes['logout'])) {
            $router->middleware('web')->get($routes['logout'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@logout')->name('keycloak.logout');
        }

        if (! empty($routes['register'])) {
            $router->middleware('web')->get($routes['register'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@register')->name('keycloak.register');
        }

        if (! empty($routes['callback'])) {
            $router->middleware('web')->get($routes['callback'], 'Vizir\KeycloakWebGuard\Controllers\AuthController@callback')->name('keycloak.callback');
        }
    }
}
