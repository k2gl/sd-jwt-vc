<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwt\Jws\JwsSigner;
use K2gl\SdJwt\Sd;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\SdJwtVcIssuer;
use K2gl\SdJwtVc\SdJwtVcVerifier;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use K2gl\SdJwtVc\X5cIssuerKeys;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use OpenSSLCertificate;

#[CoversClass(X5cIssuerKeys::class)]
final class X5cIssuerKeysTest extends SdJwtVcTestCase
{
    /** @var array{caPem: string, caB64: string, leafPem: string, leafB64: string, leafKeyPem: string}|null */
    private static ?array $pki = null;

    public function testResolvesTheLeafKeyFromATrustedChain(): void
    {
        $pki = self::pki();
        $resolver = new X5cIssuerKeys([$pki['caPem']]);

        $verifier = $resolver->resolve(null, (object) ['x5c' => [$pki['leafB64'], $pki['caB64']]]);

        // End-to-end: an SD-JWT VC signed by the leaf key verifies via x5c.
        $issuer = new SdJwtVcIssuer(JwsSigner::es256FromPem($pki['leafKeyPem']));
        $credential = $issuer->issue([
            'vct' => 'urn:example:t',
            'given_name' => Sd::hide('John'),
        ], ['x5c' => [$pki['leafB64'], $pki['caB64']]]);

        $verified = (new SdJwtVcVerifier)->verify($credential, new X5cIssuerKeys([$pki['caPem']]));

        self::assertSame('urn:example:t', $verified->vct());
        self::assertNull($verified->issuer());
    }

    public function testMissingX5cHeaderFails(): void
    {
        $this->expectException(IssuerKeyResolutionFailed::class);
        $this->expectExceptionMessage('x5c');

        (new X5cIssuerKeys([self::pki()['caPem']]))->resolve(null, (object) []);
    }

    public function testUntrustedChainFails(): void
    {
        $pki = self::pki();
        $otherCa = self::makeAuthority('Other CA');

        $this->expectException(IssuerKeyResolutionFailed::class);
        $this->expectExceptionMessage('trust anchor');

        (new X5cIssuerKeys([$otherCa['pem']]))->resolve(null, (object) ['x5c' => [$pki['leafB64'], $pki['caB64']]]);
    }

    public function testGarbageChainFails(): void
    {
        $this->expectException(IssuerKeyResolutionFailed::class);

        (new X5cIssuerKeys([self::pki()['caPem']]))->resolve(null, (object) ['x5c' => ['bm90IGEgY2VydA==']]);
    }

    public function testNoAnchorsIsRejectedUpFront(): void
    {
        $this->expectException(IssuerKeyResolutionFailed::class);

        new X5cIssuerKeys([]);
    }

    /**
     * A tiny runtime PKI: one CA, one leaf signed by it.
     *
     * @return array{caPem: string, caB64: string, leafPem: string, leafB64: string, leafKeyPem: string}
     */
    private static function pki(): array
    {
        if (self::$pki !== null) {
            return self::$pki;
        }

        $ca = self::makeAuthority('Test CA');

        $leafKey = self::newKey();
        $csr = openssl_csr_new(['commonName' => 'https://issuer.example'], $leafKey, ['digest_alg' => 'sha256']);
        self::assertNotFalse($csr);
        $leafCert = openssl_csr_sign($csr, $ca['cert'], $ca['key'], 365, ['digest_alg' => 'sha256'], 2);
        self::assertNotFalse($leafCert);
        openssl_x509_export($leafCert, $leafPem);
        openssl_pkey_export($leafKey, $leafKeyPem);

        return self::$pki = [
            'caPem' => $ca['pem'],
            'caB64' => self::pemToB64Der($ca['pem']),
            'leafPem' => (string) $leafPem,
            'leafB64' => self::pemToB64Der((string) $leafPem),
            'leafKeyPem' => (string) $leafKeyPem,
        ];
    }

    /**
     * @return array{key: OpenSSLAsymmetricKey, cert: OpenSSLCertificate, pem: string}
     */
    private static function makeAuthority(string $commonName): array
    {
        $key = self::newKey();
        $csr = openssl_csr_new(['commonName' => $commonName], $key, ['digest_alg' => 'sha256']);
        self::assertNotFalse($csr);
        $cert = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256'], 1);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $pem);

        return ['key' => $key, 'cert' => $cert, 'pem' => (string) $pem];
    }

    private static function newKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($key);

        return $key;
    }

    private static function pemToB64Der(string $pem): string
    {
        self::assertSame(1, preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $pem, $m));

        return (string) preg_replace('/\s+/', '', $m[1]);
    }
}
