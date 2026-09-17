<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Internal;

use K2gl\SdJwtVc\Exception\InvalidSdJwtVcException;
use stdClass;

/**
 * Evaluation of a claim path (draft-ietf-oauth-sd-jwt-vc Section 5.6.1.2)
 * against a verified credential: the processed payload, plus the positions of
 * the array elements that were not disclosed, so that integers and `null`
 * address the arrays as issued. A selected element that was not disclosed is
 * reported as such; nothing below it can be selected.
 *
 * @internal
 */
final class ClaimPath
{
    /**
     * @param list<string> $undisclosedPaths JSON Pointers, as issued, of undisclosed array elements
     */
    public function __construct(
        private readonly stdClass $payload,
        private readonly array $undisclosedPaths,
    ) {}

    /**
     * The claims a path selects, as JSON Pointers with array positions as
     * issued, each flagged when it is an undisclosed array element.
     *
     * @param list<string|int|null> $path
     * @return list<array{pointer: string, undisclosed: bool}>
     */
    public function select(array $path): array
    {
        /** @var list<array{value: mixed, pointer: string, undisclosed: bool}> $selected */
        $selected = [['value' => $this->payload, 'pointer' => '', 'undisclosed' => false]];

        foreach ($path as $component) {
            $next = [];

            foreach ($selected as $node) {
                if ($node['undisclosed']) {
                    continue; // its contents are unknown: nothing below it is selected
                }

                if (is_string($component)) {
                    if (! $node['value'] instanceof stdClass) {
                        throw new InvalidSdJwtVcException(sprintf('Claim path %s selects a key in something that is not an object.', json_encode($path)));
                    }

                    if (property_exists($node['value'], $component)) {
                        $next[] = ['value' => $node['value']->{$component}, 'pointer' => $node['pointer'] . '/' . self::escape($component), 'undisclosed' => false];
                    }

                    continue;
                }

                if (! is_array($node['value'])) {
                    throw new InvalidSdJwtVcException(sprintf('Claim path %s selects an element of something that is not an array.', json_encode($path)));
                }
                $positions = $this->positions($node['pointer'], count($node['value']));

                foreach ($positions as $issued => $processed) {
                    if ($component !== null && $component !== $issued) {
                        continue;
                    }
                    $next[] = $processed === null
                        ? ['value' => null, 'pointer' => $node['pointer'] . '/' . $issued, 'undisclosed' => true]
                        : ['value' => $node['value'][$processed], 'pointer' => $node['pointer'] . '/' . $issued, 'undisclosed' => false];
                }
            }
            $selected = $next;
        }

        return array_map(
            static fn (array $node): array => ['pointer' => $node['pointer'], 'undisclosed' => $node['undisclosed']],
            $selected,
        );
    }

    /**
     * The array at $pointer as issued: issued position => processed index, or
     * null where the element was not disclosed.
     *
     * @return array<int, ?int>
     */
    private function positions(string $pointer, int $processedCount): array
    {
        $undisclosed = [];
        $prefix = $pointer . '/';

        foreach ($this->undisclosedPaths as $path) {
            if (str_starts_with($path, $prefix) && preg_match('/^(0|[1-9][0-9]*)$/', substr($path, strlen($prefix))) === 1) {
                $undisclosed[(int) substr($path, strlen($prefix))] = true;
            }
        }
        $positions = [];
        $processed = 0;

        for ($issued = 0; $issued < $processedCount + count($undisclosed); $issued++) {
            $positions[$issued] = isset($undisclosed[$issued]) ? null : $processed++;
        }

        return $positions;
    }

    private static function escape(string $segment): string
    {
        return str_replace(['~', '/'], ['~0', '~1'], $segment);
    }
}
