<?php

class RoutingUpstream
{
    public static function getActiveByProfile(int $profileId): ?array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_upstreams WHERE profile_id = ? AND enabled = 1 ORDER BY id DESC LIMIT 1');
        $stmt->execute([$profileId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function saveImported(int $profileId, int $serverId, array $data): int
    {
        $config = self::normalizeConfig((string) ($data['config_content'] ?? ''));
        $parsed = self::parseConfig($config);
        $name = trim((string) ($data['name'] ?? 'niderland')) ?: 'niderland';

        $pdo = DB::conn();
        $pdo->beginTransaction();
        try {
            $pdo->prepare('UPDATE routing_upstreams SET enabled = 0 WHERE profile_id = ?')->execute([$profileId]);
            $stmt = $pdo->prepare('
                INSERT INTO routing_upstreams
                (profile_id, server_id, name, type, config_content, config_fingerprint, endpoint_host, endpoint_port, client_address, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ');
            $stmt->execute([
                $profileId,
                $serverId,
                $name,
                $parsed['type'],
                self::sanitizeRuntimeConfig($config),
                hash('sha256', $config),
                $parsed['endpoint_host'],
                $parsed['endpoint_port'],
                $parsed['client_address'],
            ]);
            $id = (int) $pdo->lastInsertId();
            $pdo->commit();
            return $id;
        } catch (Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    public static function deleteActive(int $profileId): void
    {
        DB::conn()->prepare('UPDATE routing_upstreams SET enabled = 0 WHERE profile_id = ?')->execute([$profileId]);
    }

    public static function markApplied(int $id, bool $success, ?string $error = null): void
    {
        DB::conn()->prepare('UPDATE routing_upstreams SET last_applied_at = NOW(), last_status = ?, last_error = ? WHERE id = ?')
            ->execute([$success ? 'success' : 'failed', $error, $id]);
    }

    public static function parseConfig(string $config): array
    {
        $config = self::normalizeConfig($config);
        $vars = QrUtil::parseWireGuardConfig($config);
        $endpointHost = trim((string) ($vars['hostName'] ?? ''));
        $endpointPort = (int) ($vars['port'] ?? 0);
        $privateKey = trim((string) ($vars['client_priv_key'] ?? ''));
        $serverKey = trim((string) ($vars['server_pub_key'] ?? ''));
        $address = trim((string) ($vars['client_ip'] ?? ''));

        if ($privateKey === '' || $serverKey === '' || $endpointHost === '' || $address === '') {
            throw new InvalidArgumentException('Config must include Interface PrivateKey/Address and Peer PublicKey/Endpoint');
        }
        if ($endpointPort < 1 || $endpointPort > 65535) {
            throw new InvalidArgumentException('Invalid upstream endpoint port');
        }

        $type = preg_match('/^\s*(Jc|Jmin|Jmax|S1|S2|H1|I1)\s*=/mi', $config) ? 'amneziawg_config' : 'wireguard_config';
        return [
            'type' => $type,
            'endpoint_host' => $endpointHost,
            'endpoint_port' => $endpointPort,
            'client_address' => $address,
            'masked_config' => self::maskConfig($config),
        ];
    }

    public static function maskConfig(string $config): string
    {
        return RoutingApplyHistory::maskSecrets($config);
    }

    public static function normalizeConfig(string $config): string
    {
        $config = str_replace("\r\n", "\n", $config);
        $config = str_replace("\r", "\n", $config);
        $config = trim($config);
        if ($config === '') {
            throw new InvalidArgumentException('Upstream config is required');
        }
        if (strlen($config) > 65535) {
            throw new InvalidArgumentException('Upstream config is too large');
        }
        return $config . "\n";
    }

    private static function sanitizeRuntimeConfig(string $config): string
    {
        $lines = [];
        foreach (explode("\n", $config) as $line) {
            if (preg_match('/^\s*(DNS|Table|PostUp|PostDown|PreUp|PreDown|SaveConfig)\s*=/i', $line)) {
                continue;
            }
            $lines[] = $line;
        }
        $clean = trim(implode("\n", $lines)) . "\n";
        if (!preg_match('/^\s*Table\s*=/mi', $clean)) {
            $clean = preg_replace('/(\[Interface\]\s*)/i', "$1Table = off\n", $clean, 1);
        }
        return $clean;
    }
}
