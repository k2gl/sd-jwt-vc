<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\Dsse\PublicKey;
use K2gl\Dsse\Verifier;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use OpenSSLCertificate;
use stdClass;
use Throwable;

/**
 * Inline X.509 key discovery (draft-ietf-oauth-sd-jwt-vc Section 2.5): take
 * the end-entity certificate from the `x5c` JOSE header, validate the chain
 * up to one of the configured trust anchors, and use the end-entity public
 * key as the Issuer key.
 *
 * Scope: signature chain, validity windows, and trust-anchor membership
 * (by exact certificate match). Revocation checking and X.509 policy/name
 * constraints are out of scope — pair with an ecosystem policy if you need
 * them.
 */
final class X5cIssuerKeys implements IssuerKeyResolver
{
    /** @var list<string> DER-encoded trusted certificates */
    private readonly array $anchors;

    /**
     * @param list<string> $trustedCertificates Trust anchors as PEM strings.
     */
    public function __construct(array $trustedCertificates, private readonly ?int $clock = null)
    {
        $anchors = [];

        foreach ($trustedCertificates as $pem) {
            $anchors[] = self::der($pem);
        }

        if ($anchors === []) {
            throw new IssuerKeyResolutionFailed('At least one trust anchor certificate is required.');
        }

        $this->anchors = $anchors;
    }

    public function resolve(?string $issuer, stdClass $header): Verifier
    {
        $x5c = $header->x5c ?? null;

        if (! is_array($x5c) || $x5c === []) {
            throw new IssuerKeyResolutionFailed('The JOSE header has no "x5c" certificate chain.');
        }

        $chain = [];

        foreach ($x5c as $encoded) {
            if (! is_string($encoded)) {
                throw new IssuerKeyResolutionFailed('Malformed "x5c" header: expected base64 DER strings.');
            }

            $chain[] = self::certificate($encoded);
        }

        $this->checkValidity($chain);
        $this->checkSignatures($chain);
        $this->checkAnchored($chain);

        return self::leafVerifier($chain[0]);
    }

    /**
     * @param list<array{cert: OpenSSLCertificate, der: string}> $chain
     */
    private function checkValidity(array $chain): void
    {
        $now = $this->clock ?? time();

        foreach ($chain as $entry) {
            $parsed = openssl_x509_parse($entry['cert']);

            if ($parsed === false
                || ! is_int($parsed['validFrom_time_t'] ?? null)
                || ! is_int($parsed['validTo_time_t'] ?? null)) {
                throw new IssuerKeyResolutionFailed('Unable to parse a certificate in the "x5c" chain.');
            }

            if ($now < $parsed['validFrom_time_t'] || $now > $parsed['validTo_time_t']) {
                throw new IssuerKeyResolutionFailed('A certificate in the "x5c" chain is expired or not yet valid.');
            }
        }
    }

    /**
     * Each certificate must be signed by the next one; the last must be
     * self-signed or signed by a trust anchor.
     *
     * @param list<array{cert: OpenSSLCertificate, der: string}> $chain
     */
    private function checkSignatures(array $chain): void
    {
        $count = count($chain);

        for ($i = 0; $i < $count; $i++) {
            $issuerCandidates = $i + 1 < $count
                ? [$chain[$i + 1]['cert']]
                : [...array_map(static fn (string $der): OpenSSLCertificate => self::fromDer($der), $this->anchors), $chain[$i]['cert']];

            $verified = false;

            foreach ($issuerCandidates as $candidate) {
                $key = openssl_pkey_get_public($candidate);

                if ($key !== false && openssl_x509_verify($chain[$i]['cert'], $key) === 1) {
                    $verified = true;

                    break;
                }
            }

            if (! $verified) {
                throw new IssuerKeyResolutionFailed('The "x5c" chain does not verify.');
            }
        }
    }

    /**
     * @param list<array{cert: OpenSSLCertificate, der: string}> $chain
     */
    private function checkAnchored(array $chain): void
    {
        foreach ($chain as $entry) {
            foreach ($this->anchors as $anchor) {
                if (hash_equals($anchor, $entry['der'])) {
                    return;
                }
            }
        }

        // The chain may also be issued BY an anchor without containing it.
        $last = $chain[count($chain) - 1]['cert'];

        foreach ($this->anchors as $anchor) {
            $key = openssl_pkey_get_public(self::fromDer($anchor));

            if ($key !== false && openssl_x509_verify($last, $key) === 1) {
                return;
            }
        }

        throw new IssuerKeyResolutionFailed('The "x5c" chain does not lead to a configured trust anchor.');
    }

    /**
     * @return array{cert: OpenSSLCertificate, der: string}
     */
    private static function certificate(string $base64Der): array
    {
        $der = base64_decode($base64Der, true);

        if ($der === false) {
            throw new IssuerKeyResolutionFailed('Malformed "x5c" header: invalid base64.');
        }

        return ['cert' => self::fromDer($der), 'der' => $der];
    }

    private static function fromDer(string $der): OpenSSLCertificate
    {
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64) . '-----END CERTIFICATE-----';
        $cert = @openssl_x509_read($pem); // warns on garbage; the false branch throws instead

        if ($cert === false) {
            throw new IssuerKeyResolutionFailed('Unable to parse a certificate in the "x5c" chain.');
        }

        return $cert;
    }

    private static function der(string $pem): string
    {
        if (preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $pem, $matches) !== 1) {
            throw new IssuerKeyResolutionFailed('Trust anchors must be PEM certificates.');
        }

        $der = base64_decode(preg_replace('/\s+/', '', $matches[1]) ?? '', true);

        if ($der === false) {
            throw new IssuerKeyResolutionFailed('Trust anchors must be PEM certificates.');
        }

        return $der;
    }

    private static function leafVerifier(mixed $leaf): Verifier
    {
        /** @var array{cert: OpenSSLCertificate, der: string} $leaf */
        $key = openssl_pkey_get_public($leaf['cert']);

        if ($key === false) {
            throw new IssuerKeyResolutionFailed('Unable to extract the public key from the end-entity certificate.');
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['key']) || ! is_string($details['key'])) {
            throw new IssuerKeyResolutionFailed('Unable to export the end-entity public key.');
        }

        try {
            return PublicKey::fromPem($details['key']);
        } catch (Throwable $e) {
            throw new IssuerKeyResolutionFailed('Unsupported end-entity key: ' . $e->getMessage(), previous: $e);
        }
    }
}
