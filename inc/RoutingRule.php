<?php

class RoutingRule
{
    public static function listByProfile(int $profileId): array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_domain_rules WHERE profile_id = ? ORDER BY priority ASC, domain ASC');
        $stmt->execute([$profileId]);
        return $stmt->fetchAll();
    }

    public static function listEnabledByProfile(int $profileId): array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_domain_rules WHERE profile_id = ? AND enabled = 1 ORDER BY priority ASC, domain ASC');
        $stmt->execute([$profileId]);
        return $stmt->fetchAll();
    }

    public static function find(int $ruleId): ?array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_domain_rules WHERE id = ? LIMIT 1');
        $stmt->execute([$ruleId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function create(int $profileId, array $data): int
    {
        $data = self::validate($data);
        $stmt = DB::conn()->prepare('
            INSERT INTO routing_domain_rules
            (profile_id, domain, match_type, add_to_direct, add_to_upstream, add_to_no_quic, enabled, priority, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([$profileId, $data['domain'], $data['match_type'], $data['add_to_direct'], $data['add_to_upstream'], $data['add_to_no_quic'], $data['enabled'], $data['priority'], $data['comment']]);
        return (int) DB::conn()->lastInsertId();
    }

    public static function update(int $ruleId, array $data): void
    {
        $data = self::validate($data);
        DB::conn()->prepare('
            UPDATE routing_domain_rules SET domain = ?, match_type = ?, add_to_direct = ?, add_to_upstream = ?,
              add_to_no_quic = ?, enabled = ?, priority = ?, comment = ? WHERE id = ?
        ')->execute([$data['domain'], $data['match_type'], $data['add_to_direct'], $data['add_to_upstream'], $data['add_to_no_quic'], $data['enabled'], $data['priority'], $data['comment'], $ruleId]);
    }

    public static function delete(int $ruleId): void
    {
        DB::conn()->prepare('DELETE FROM routing_domain_rules WHERE id = ?')->execute([$ruleId]);
    }

    private static function validate(array $data): array
    {
        $domain = strtolower(trim((string) ($data['domain'] ?? '')));
        if ($domain === '') {
            throw new InvalidArgumentException('Domain is required');
        }
        if (preg_match('#https?://#i', $domain) || str_contains($domain, '/')) {
            throw new InvalidArgumentException('Domain must not contain scheme or path');
        }
        if (!preg_match('/^\.?[a-z0-9][a-z0-9.-]*[a-z0-9]$/i', $domain)) {
            throw new InvalidArgumentException('Invalid domain');
        }
        $matchType = (string) ($data['match_type'] ?? 'suffix');
        if (!in_array($matchType, ['exact', 'suffix'], true)) {
            throw new InvalidArgumentException('Invalid match type');
        }
        $direct = !empty($data['add_to_direct']) ? 1 : 0;
        $upstream = !empty($data['add_to_upstream']) ? 1 : 0;
        $noQuic = !empty($data['add_to_no_quic']) ? 1 : 0;
        if (!$direct && !$upstream && !$noQuic) {
            throw new InvalidArgumentException('Select at least one target');
        }
        if ($direct && $upstream) {
            throw new InvalidArgumentException('Direct/Openmail and Niderland cannot be enabled together in MVP');
        }
        return [
            'domain' => $domain,
            'match_type' => $matchType,
            'add_to_direct' => $direct,
            'add_to_upstream' => $upstream,
            'add_to_no_quic' => $noQuic,
            'enabled' => !empty($data['enabled']) ? 1 : 0,
            'priority' => (int) ($data['priority'] ?? 100),
            'comment' => trim((string) ($data['comment'] ?? '')) ?: null,
        ];
    }
}
