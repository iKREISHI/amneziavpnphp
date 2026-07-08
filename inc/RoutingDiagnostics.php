<?php

class RoutingDiagnostics
{
    public static function parseStatusOutput(string $stdout): array
    {
        $rows = [];
        foreach (preg_split('/\R/', trim($stdout)) as $line) {
            if ($line === '') {
                continue;
            }
            $parts = explode(':', $line, 2);
            $rows[] = [
                'name' => trim($parts[0] ?? $line),
                'value' => trim($parts[1] ?? ''),
                'ok' => !preg_match('/missing| no$|failed|unknown/i', $line),
            ];
        }
        return $rows;
    }
}
