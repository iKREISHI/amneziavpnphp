<?php

class RoutingIpSource
{
    private const TARGETS = ['direct_ip', 'niderland_ip', 'no_quic'];

    public static function listByProfile(int $profileId): array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_ip_sources WHERE profile_id = ? ORDER BY name ASC');
        $stmt->execute([$profileId]);
        return $stmt->fetchAll();
    }

    public static function listEnabledByProfile(int $profileId): array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_ip_sources WHERE profile_id = ? AND enabled = 1 ORDER BY name ASC');
        $stmt->execute([$profileId]);
        return $stmt->fetchAll();
    }

    public static function create(int $profileId, array $data): int
    {
        $data = self::validate($data);
        DB::conn()->prepare('
            INSERT INTO routing_ip_sources (profile_id, name, target_ipset, source_type, url, enabled, refresh_interval_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ')->execute([$profileId, $data['name'], $data['target_ipset'], $data['source_type'], $data['url'], $data['enabled'], $data['refresh_interval_seconds']]);
        return (int) DB::conn()->lastInsertId();
    }

    public static function update(int $sourceId, array $data): void
    {
        $data = self::validate($data);
        DB::conn()->prepare('
            UPDATE routing_ip_sources SET name = ?, target_ipset = ?, source_type = ?, url = ?, enabled = ?, refresh_interval_seconds = ?
            WHERE id = ?
        ')->execute([$data['name'], $data['target_ipset'], $data['source_type'], $data['url'], $data['enabled'], $data['refresh_interval_seconds'], $sourceId]);
    }

    public static function delete(int $sourceId): void
    {
        DB::conn()->prepare('DELETE FROM routing_ip_sources WHERE id = ?')->execute([$sourceId]);
    }

    private static function validate(array $data): array
    {
        $name = trim((string) ($data['name'] ?? ''));
        $target = (string) ($data['target_ipset'] ?? '');
        $type = (string) ($data['source_type'] ?? 'url_cidr_list');
        $url = trim((string) ($data['url'] ?? ''));
        if ($name === '') {
            throw new InvalidArgumentException('Name is required');
        }
        if (!in_array($target, self::TARGETS, true)) {
            throw new InvalidArgumentException('Invalid target ipset');
        }
        if (!in_array($type, ['url_cidr_list', 'url_ip_list'], true)) {
            throw new InvalidArgumentException('Invalid source type');
        }
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('Invalid URL');
        }
        return [
            'name' => $name,
            'target_ipset' => $target,
            'source_type' => $type,
            'url' => $url,
            'enabled' => !empty($data['enabled']) ? 1 : 0,
            'refresh_interval_seconds' => max(60, (int) ($data['refresh_interval_seconds'] ?? 86400)),
        ];
    }
}
