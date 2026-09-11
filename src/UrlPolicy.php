<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;

/**
 * Which URLs the resolver may connect to (draft-ietf-oauth-sd-jwt-vc
 * Section 3 and Section 7.1). The URLs come from untrusted input — the `iss`
 * claim of a credential — so every one of them, redirect targets included,
 * must be HTTPS and must not point at an internal address.
 *
 * Literal IP hosts are checked directly; DNS names are resolved and each
 * address checked, unless `resolveHosts` is turned off (air-gapped tests,
 * or a deployment that pins its egress elsewhere).
 */
final class UrlPolicy
{
    public function __construct(private readonly bool $resolveHosts = true) {}

    /**
     * @throws IssuerKeyResolutionFailed when the URL must not be dereferenced
     */
    public function assertAllowed(string $url): void
    {
        $parts = parse_url($url);

        if ($parts === false || strtolower($parts['scheme'] ?? '') !== 'https' || ! isset($parts['host'])) {
            throw new IssuerKeyResolutionFailed(sprintf('Refusing to fetch %s: not an HTTPS URL.', $url));
        }

        $host = strtolower(trim($parts['host'], '[]'));

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            throw new IssuerKeyResolutionFailed(sprintf('Refusing to fetch %s: the host is internal.', $url));
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            self::assertPublicAddress($host, $url);

            return;
        }

        if (! $this->resolveHosts) {
            return;
        }

        foreach (self::resolve($host, $url) as $address) {
            self::assertPublicAddress($address, $url);
        }
    }

    /**
     * @return non-empty-list<string>
     */
    private static function resolve(string $host, string $url): array
    {
        $addresses = gethostbynamel($host) ?: [];

        foreach (dns_get_record($host, DNS_AAAA) ?: [] as $record) {
            if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                $addresses[] = $record['ipv6'];
            }
        }

        if ($addresses === []) {
            throw new IssuerKeyResolutionFailed(sprintf('Refusing to fetch %s: the host does not resolve.', $url));
        }

        return $addresses;
    }

    private static function assertPublicAddress(string $address, string $url): void
    {
        $public = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);

        if ($public === false) {
            throw new IssuerKeyResolutionFailed(sprintf(
                'Refusing to fetch %s: it points to the internal address %s.',
                $url,
                $address,
            ));
        }
    }
}
