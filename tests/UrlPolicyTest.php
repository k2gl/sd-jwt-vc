<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\UrlPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(UrlPolicy::class)]
final class UrlPolicyTest extends TestCase
{
    #[DataProvider('allowedUrls')]
    public function testAllowsPublicHttpsUrls(string $url): void
    {
        // arrange
        $policy = new UrlPolicy(resolveHosts: false);

        // act + assert
        fact(static fn () => $policy->assertAllowed($url))->doesNotThrow();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function allowedUrls(): array
    {
        return [
            'dns name'          => ['https://example.com/.well-known/jwt-vc-issuer'],
            'public ipv4'       => ['https://93.184.216.34/meta'],
            'public ipv6'       => ['https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/meta'],
            'upper-case scheme' => ['HTTPS://example.com/meta'],
        ];
    }

    #[DataProvider('refusedUrls')]
    public function testRefusesInternalOrPlainUrls(string $url, string $message): void
    {
        // arrange
        $policy = new UrlPolicy(resolveHosts: false);

        // act + assert
        fact(static fn () => $policy->assertAllowed($url))->throws(IssuerKeyResolutionFailed::class, $message);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function refusedUrls(): array
    {
        return [
            'http'             => ['http://example.com/meta', 'not an HTTPS URL'],
            'no host'          => ['https:///meta', 'not an HTTPS URL'],
            'localhost'        => ['https://localhost/meta', 'the host is internal'],
            'localhost domain' => ['https://api.localhost/meta', 'the host is internal'],
            'loopback'         => ['https://127.0.0.1/meta', 'internal address 127.0.0.1'],
            'private 10/8'     => ['https://10.1.2.3/meta', 'internal address 10.1.2.3'],
            'private 172.16'   => ['https://172.16.0.1/meta', 'internal address 172.16.0.1'],
            'private 192.168'  => ['https://192.168.1.1/meta', 'internal address 192.168.1.1'],
            'link-local'       => ['https://169.254.169.254/latest/meta-data', 'internal address 169.254.169.254'],
            'ipv6 loopback'    => ['https://[::1]/meta', 'internal address ::1'],
            'ipv6 unique local' => ['https://[fd00::1]/meta', 'internal address fd00::1'],
        ];
    }
}
