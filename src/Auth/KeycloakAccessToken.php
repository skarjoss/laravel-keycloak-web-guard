<?php

namespace Vizir\KeycloakWebGuard\Auth;

use Exception;

class KeycloakAccessToken
{
    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var string
     */
    protected $refreshToken;

    /**
     * @var string
     */
    protected $idToken;

    /**
     * @var int
     */
    protected $expires;

    /**
     * Constructs an access token.
     *
     * @param array $data The token from Keycloak as array.
     */
    public function __construct($data = [])
    {
        $data = (array) $data;

        if (! empty($data['access_token'])) {
            $this->accessToken = $data['access_token'];
        }

        if (! empty($data['refresh_token'])) {
            $this->refreshToken = $data['refresh_token'];
        }

        if (! empty($data['id_token'])) {
            $this->idToken = $data['id_token'];
        }

        if (! empty($data['expires_in'])) {
            $this->expires = (int) $data['expires_in'];
        }
    }

    /**
     * Get AccessToken
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Get RefreshToken
     *
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Get IdToken
     *
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * Check access token has expired
     *
     * @param  int $leeway Seconds of tolerance to refresh the token earlier
     * @return boolean
     */
    public function hasExpired($leeway = 0)
    {
        $exp = $this->parseAccessToken();
        $exp = $exp['exp'] ?? '';

        return (time() + (int) $leeway) >= (int) $exp;
    }

    /**
     * Check the ID Token
     *
     * @param  array $claims
     * @param  int   $leeway Seconds of tolerance for clock skew
     * @throws Exception
     * @return void
     */
    public function validateIdToken($claims, $leeway = 0)
    {
        $token = $this->parseIdToken();
        if (empty($token)) {
            throw new Exception('ID Token is invalid.');
        }

        $default = array(
            'exp' => 0,
            'aud' => '',
            'iss' => '',
        );

        $token = array_merge($default, $token);
        $claims = array_merge($default, (array) $claims);

        // Validate expiration
        if ((time() - (int) $leeway) >= (int) $token['exp']) {
            throw new Exception('ID Token already expired.');
        }

        // Validate issuer
        if (empty($claims['iss']) || $claims['iss'] !== $token['iss']) {
            throw new Exception('Access Token has a wrong issuer: must contain issuer from OpenId.');
        }

        // Validate audience
        $audience = (array) $token['aud'];
        if (empty($claims['aud']) || ! in_array($claims['aud'], $audience, true)) {
            throw new Exception('Access Token has a wrong audience: must contain clientId.');
        }

        if (count($audience) > 1 && empty($token['azp'])) {
            throw new Exception('Access Token has a wrong audience: must contain azp claim.');
        }

        if (! empty($token['azp']) && $claims['aud'] !== $token['azp']) {
            throw new Exception('Access Token has a wrong audience: has azp but is not the clientId.');
        }
    }

    /**
     * Validate sub from ID token
     *
     * @return boolean
     */
    public function validateSub($userSub)
    {
        $sub = $this->parseIdToken();
        $sub = $sub['sub'] ?? '';

        return $sub === $userSub;
    }

    /**
     * Verify the signature of a JWT with the realm public key
     *
     * @param  string $jwt
     * @param  string $publicKey Realm public key (RS256)
     * @param  array  $algorithms Allowed algorithms
     * @throws Exception
     * @return bool
     */
    public function verifySignature($jwt, $publicKey, array $algorithms = ['RS256'])
    {
        if (empty($publicKey)) {
            throw new Exception('Signature verification is enabled but the realm public key is not configured.');
        }

        if (! function_exists('openssl_verify')) {
            throw new Exception('The openssl extension is required to verify token signatures.');
        }

        $segments = is_string($jwt) ? explode('.', $jwt) : [];

        if (count($segments) !== 3) {
            throw new Exception('Token has an invalid JWT format.');
        }

        list($headerB64, $payloadB64, $signatureB64) = $segments;

        $header = json_decode($this->base64UrlDecode($headerB64), true);
        $algorithm = is_array($header) ? ($header['alg'] ?? '') : '';

        if (! in_array($algorithm, $algorithms, true)) {
            throw new Exception('Token signing algorithm [' . $algorithm . '] is not allowed.');
        }

        $digests = array(
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        );

        if (! isset($digests[$algorithm])) {
            throw new Exception('Token signing algorithm [' . $algorithm . '] is not supported.');
        }

        $signature = $this->base64UrlDecode($signatureB64);
        $key = $this->formatPublicKey($publicKey);

        if (openssl_verify($headerB64 . '.' . $payloadB64, $signature, $key, $digests[$algorithm]) !== 1) {
            throw new Exception('Token signature is invalid.');
        }

        return true;
    }

    /**
     * Wrap a Keycloak realm public key into a PEM certificate
     *
     * @param  string $publicKey
     * @return string
     */
    protected function formatPublicKey($publicKey)
    {
        $publicKey = trim((string) $publicKey);

        // Accept an already formatted public key or X.509 certificate as-is
        if (strpos($publicKey, 'BEGIN PUBLIC KEY') !== false || strpos($publicKey, 'BEGIN CERTIFICATE') !== false) {
            return $publicKey;
        }

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split($publicKey, 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Parse the Access Token
     *
     * @return array
     */
    public function parseAccessToken()
    {
        return $this->parseToken($this->accessToken);
    }

    /**
     * Parse the Id Token
     *
     * @return array
     */
    public function parseIdToken()
    {
        return $this->parseToken($this->idToken);
    }

    /**
     * Parse the Access Token header
     *
     * @return array
     */
    public function parseAccessTokenHeader()
    {
        return $this->parseHeader($this->accessToken);
    }

    /**
     * Parse the Id Token header
     *
     * @return array
     */
    public function parseIdTokenHeader()
    {
        return $this->parseHeader($this->idToken);
    }

    /**
     * Get token (access/refresh/id) data
     *
     * @param string $token
     * @return array
     */
    protected function parseToken($token)
    {
        if (! is_string($token)) {
            return [];
        }

        $token = explode('.', $token);

        if (! isset($token[1])) {
            return [];
        }

        $token = $this->base64UrlDecode($token[1]);

        return json_decode($token, true) ?: [];
    }

    /**
     * Get the JWT header
     *
     * @param string $token
     * @return array
     */
    protected function parseHeader($token)
    {
        if (! is_string($token)) {
            return [];
        }

        $token = explode('.', $token);

        if (! isset($token[0])) {
            return [];
        }

        $token = $this->base64UrlDecode($token[0]);

        return json_decode($token, true) ?: [];
    }

    /**
     * Base64UrlDecode string
     *
     * @link https://www.php.net/manual/pt_BR/function.base64-encode.php#103849
     *
     * @param  string $data
     * @return string
     */
    protected function base64UrlDecode($data)
    {
        $data = strtr((string) $data, '-_', '+/');
        $remainder = strlen($data) % 4;

        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode($data);
    }
}
