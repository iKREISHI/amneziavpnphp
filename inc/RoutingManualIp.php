<?php

class RoutingManualIp
{
    private const TARGETS = ['direct_ip', 'niderland_ip', 'no_quic'];

    public static function listByProfile(int $profileId): array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_manual_ips WHERE profile_id = ? ORDER BY target_ipset ASC, value ASC');
        $stmt->execute([$profileId]);
        return $stmt->fetchAll();
    }

    public static function listEnabledByProfile(int $profileId): array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_manual_ips WHERE profile_id = ? AND enabled = 1 ORDER BY target_ipset ASC, value ASC');
        $stmt->execute([$profileId]);
        return $stmt->fetchAll();
    }

    public static function create(int $profileId, array $data): int
    {
        $data = self::validate($data);
        DB::conn()->prepare('INSERT INTO routing_manual_ips (profile_id, target_ipset, value, enabled, comment) VALUES (?, ?, ?, ?, ?)')
            ->execute([$profileId, $data['target_ipset'], $data['value'], $data['enabled'], $data['comment']]);
        return (int) DB::conn()->lastInsertId();
    }

    public static function update(int $manualIpId, array $data): void
    {
        $data = self::validate($data);
        DB::conn()->prepare('UPDATE routing_manual_ips SET target_ipset = ?, value = ?, enabled = ?, comment = ? WHERE id = ?')
            ->execute([$data['target_ipset'], $data['value'], $data['enabled'], $data['comment'], $manualIpId]);
    }

    public static function delete(int $manualIpId): void
    {
        DB::conn()->prepare('DELETE FROM routing_manual_ips WHERE id = ?')->execute([$manualIpId]);
    }

    private static function validate(array $data): array
    {
        $target = (string) ($data['target_ipset'] ?? '');
        $value = trim((string) ($data['value'] ?? ''));
        if (!in_array($target, self::TARGETS, true)) {
            throw new InvalidArgumentException('Invalid target ipset');
        }
        if (!self::validIpv4OrCidr($value)) {
            throw new InvalidArgumentException('Invalid IPv4 or CIDR');
        }
        if ($target !== 'direct_ip' && str_contains($value, '/')) {
            throw new InvalidArgumentException('CIDR is only allowed for direct_ip');
        }
        return [
            'target_ipset' => $target,
            'value' => $value,
            'enabled' => !empty($data['enabled']) ? 1 : 0,
            'comment' => trim((string) ($data['comment'] ?? '')) ?: null,
        ];
    }

    private static function validIpv4OrCidr(string $value): bool
    {
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return true;
        }
        if (!preg_match('#^([^/]+)/([0-9]|[12][0-9]|3[0-2])$#', $value, $m)) {
            return false;
        }
        return (bool) filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }
}
