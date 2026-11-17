<?php

namespace Vizir\KeycloakWebGuard\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Vizir\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Vizir\KeycloakWebGuard\Facades\KeycloakWeb;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        $url = KeycloakWeb::getLogoutUrl();
        KeycloakWeb::forgetToken();

        // Close the application session too (shared computers): keeping the
        // Laravel session alive would leave data of the previous user behind.
        try {
            request()->session()->invalidate();
            request()->session()->regenerateToken();
        } catch (\Throwable $e) {
            // No session available
        }

        return redirect($url);
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        $url = KeycloakWeb::getRegisterUrl();
        return redirect($url);
    }

    /**
     * Keycloak callback page
     *
     * @throws KeycloakCallbackException
     * @return view
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak (access_denied, login_required...)
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            Log::warning('[Keycloak] Authorization endpoint returned an error.', [
                'error' => substr((string) $request->input('error'), 0, 120),
                'ip' => $request->ip(),
            ]);

            if ((bool) config('keycloak-web.throw_callback_errors', false)) {
                throw new KeycloakCallbackException($error);
            }

            return redirect($this->failureUrl())->withErrors(['sso' => $error]);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! KeycloakWeb::validateState($state)) {
            $failures = KeycloakWeb::registerFailedState();

            // Do not log the authorization code or the session state: they are
            // live credentials. Only a non reversible prefix of the state.
            Log::warning('[Keycloak] Callback with an invalid state.', [
                'state_prefix' => is_string($state) ? substr($state, 0, 8) : null,
                'ip' => $request->ip(),
                'user_agent' => substr((string) $request->userAgent(), 0, 120),
                'attempts' => $failures,
            ]);

            $maxFailures = (int) config('keycloak-web.max_state_failures', 3);

            if ($maxFailures > 0 && $failures >= $maxFailures) {
                // Break a possible redirect loop instead of bouncing forever.
                KeycloakWeb::forgetState();
                KeycloakWeb::forgetFailedState();

                return redirect($this->failureUrl())->withErrors([
                    'sso' => 'The login session could not be validated. Please try again.',
                ]);
            }

            return redirect(route('keycloak.login'));
        }

        // Change code for token
        $code = $request->input('code');

        if (empty($code)) {
            return redirect(route('keycloak.login'));
        }

        $token = KeycloakWeb::getAccessToken($code);

        if (empty($token)) {
            // Network problem or Keycloak error while exchanging the code.
            // Do not bounce the user to the identity provider forever.
            Log::error('[Keycloak] The authorization code could not be exchanged for tokens.', [
                'ip' => $request->ip(),
            ]);

            return redirect($this->failureUrl())->withErrors([
                'sso' => 'The login could not be completed. Please try again.',
            ]);
        }

        if (Auth::validate($token)) {
            KeycloakWeb::consumeState($state);
            KeycloakWeb::forgetFailedState();

            // Prevent session fixation: a new identity gets a new session id
            try {
                $request->session()->regenerate();
            } catch (\Throwable $e) {
                // No session available (stateless request)
            }

            $url = config('keycloak-web.redirect_url', '/admin');
            return redirect()->intended($url);
        }

        Log::warning('[Keycloak] Token validation failed after the callback.', [
            'ip' => $request->ip(),
        ]);

        return redirect($this->failureUrl())->withErrors([
            'sso' => 'The session could not be validated. Please try again.',
        ]);
    }

    /**
     * URL used when the SSO flow cannot be completed
     *
     * @return string
     */
    protected function failureUrl()
    {
        $url = config('keycloak-web.failure_redirect');

        return ! empty($url) ? $url : route('keycloak.login');
    }
}
