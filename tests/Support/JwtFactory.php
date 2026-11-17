<?php

namespace Vizir\KeycloakWebGuard\Tests\Support;

/**
 * Utilidades para fabricar JWTs válidos (RS256) y tokens de prueba.
 */
class JwtFactory
{
    private static $privateKey;
    private static $publicKey;

    /**
     * Genera (y cachea) un par de claves RSA para las pruebas.
     *
     * @return array{0: string, 1: string} [privateKey, publicKeyPem]
     */
    public static function keys(): array
    {
        if (self::$privateKey === null) {
            $resource = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            openssl_pkey_export($resource, self::$privateKey);
            self::$publicKey = openssl_pkey_get_details($resource)['key'];
        }

        return [self::$privateKey, self::$publicKey];
    }

    /**
     * Clave pública sin las cabeceras PEM (como la entrega Keycloak).
     */
    public static function barePublicKey(): string
    {
        [, $publicKey] = self::keys();

        return preg_replace('/-----[^-]+-----|\s/', '', $publicKey);
    }

    /**
     * JWT firmado con RS256.
     */
    public static function signed(array $claims, array $header = ['alg' => 'RS256', 'typ' => 'JWT']): string
    {
        [$privateKey] = self::keys();

        $encodedHeader = self::base64Url(json_encode($header));
        $encodedPayload = self::base64Url(json_encode($claims));

        openssl_sign("$encodedHeader.$encodedPayload", $signature, $privateKey, OPENSSL_ALGO_SHA256);

        return "$encodedHeader.$encodedPayload." . self::base64Url($signature);
    }

    /**
     * JWT sin firmar (para pruebas de formato/alg).
     */
    public static function unsigned(array $claims, array $header = ['alg' => 'none']): string
    {
        return self::base64Url(json_encode($header)) . '.' . self::base64Url(json_encode($claims)) . '.';
    }

    /**
     * Claims por defecto de un usuario de BGR.
     */
    public static function claims(array $overrides = []): array
    {
        return array_merge([
            'sub' => '8c1f-user',
            'email' => 'agente@bgr.com.ec',
            'given_name' => 'Ana',
            'family_name' => 'Pérez',
            'iss' => 'https://sso.test/realms/bgr_oidc1',
            'aud' => 'voc-bgr-prod',
            'azp' => 'voc-bgr-prod',
            'exp' => time() + 300,
            'iat' => time(),
        ], $overrides);
    }

    /**
     * Token (firmado) que expira en N segundos.
     */
    public static function tokenExpiringIn(int $seconds, array $overrides = []): string
    {
        return self::signed(self::claims(array_merge(['exp' => time() + $seconds], $overrides)));
    }

    public static function base64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
