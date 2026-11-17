<?php

namespace Vizir\KeycloakWebGuard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Vizir\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Vizir\KeycloakWebGuard\Tests\Support\JwtFactory;

class KeycloakAccessTokenTest extends TestCase
{
    private function tokenFrom(string $jwt): KeycloakAccessToken
    {
        return new KeycloakAccessToken(['access_token' => $jwt, 'id_token' => $jwt, 'expires_in' => 300]);
    }

    public function test_it_verifies_a_valid_signature_with_a_pem_key(): void
    {
        $jwt = JwtFactory::signed(JwtFactory::claims());
        [, $publicKey] = JwtFactory::keys();

        $this->assertTrue($this->tokenFrom($jwt)->verifySignature($jwt, $publicKey));
    }

    public function test_it_verifies_a_valid_signature_with_a_bare_key(): void
    {
        $jwt = JwtFactory::signed(JwtFactory::claims());

        $this->assertTrue($this->tokenFrom($jwt)->verifySignature($jwt, JwtFactory::barePublicKey()));
    }

    public function test_it_rejects_a_tampered_payload(): void
    {
        $jwt = JwtFactory::signed(JwtFactory::claims());
        $parts = explode('.', $jwt);
        $tampered = $parts[0] . '.' . JwtFactory::base64Url(json_encode(JwtFactory::claims([
            'email' => 'attacker@evil.com',
        ]))) . '.' . $parts[2];

        $this->expectExceptionMessage('Token signature is invalid.');

        $this->tokenFrom($jwt)->verifySignature($tampered, JwtFactory::barePublicKey());
    }

    public function test_it_rejects_the_none_algorithm(): void
    {
        $unsigned = JwtFactory::unsigned(JwtFactory::claims());

        $this->expectExceptionMessage('is not allowed');

        $this->tokenFrom($unsigned)->verifySignature($unsigned, JwtFactory::barePublicKey());
    }

    public function test_it_requires_a_public_key(): void
    {
        $jwt = JwtFactory::signed(JwtFactory::claims());

        $this->expectExceptionMessage('realm public key is not configured');

        $this->tokenFrom($jwt)->verifySignature($jwt, null);
    }

    public function test_expiration_without_leeway(): void
    {
        $token = $this->tokenFrom(JwtFactory::tokenExpiringIn(300));

        $this->assertFalse($token->hasExpired());
        $this->assertTrue($token->hasExpired(400));
    }

    public function test_it_validates_issuer_and_audience(): void
    {
        $token = $this->tokenFrom(JwtFactory::tokenExpiringIn(300));

        $token->validateIdToken([
            'aud' => 'voc-bgr-prod',
            'iss' => 'https://sso.test/realms/bgr_oidc1',
        ]);

        $this->expectExceptionMessage('wrong audience');
        $token->validateIdToken([
            'aud' => 'another-client',
            'iss' => 'https://sso.test/realms/bgr_oidc1',
        ]);
    }

    public function test_it_rejects_an_expired_id_token(): void
    {
        $token = $this->tokenFrom(JwtFactory::tokenExpiringIn(-3600));

        $this->expectExceptionMessage('already expired');

        $token->validateIdToken([
            'aud' => 'voc-bgr-prod',
            'iss' => 'https://sso.test/realms/bgr_oidc1',
        ]);
    }

    public function test_leeway_accepts_a_recently_expired_id_token(): void
    {
        $token = $this->tokenFrom(JwtFactory::tokenExpiringIn(-30));

        $token->validateIdToken([
            'aud' => 'voc-bgr-prod',
            'iss' => 'https://sso.test/realms/bgr_oidc1',
        ], 60);

        $this->assertTrue(true);
    }

    public function test_it_parses_claims_with_irregular_padding(): void
    {
        $token = $this->tokenFrom(JwtFactory::tokenExpiringIn(300, ['sub' => 'abc']));

        $this->assertSame('abc', $token->parseAccessToken()['sub']);
    }
}
