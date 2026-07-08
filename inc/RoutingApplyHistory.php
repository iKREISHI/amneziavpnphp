<?php

class RoutingApplyHistory
{
    public static function create(int $profileId, int $serverId, string $action, ?int $userId = null): int
    {
        $allowed = ['apply', 'warmup', 'check', 'rollback', 'upstream_apply', 'upstream_test'];
        if (!in_array($action, $allowed, true)) {
            throw new InvalidArgumentException('Invalid history action');
        }
        DB::conn()->prepare('
            INSERT INTO routing_apply_history (profile_id, server_id, action, status, created_by_user_id)
            VALUES (?, ?, ?, ?, ?)
        ')->execute([$profileId, $serverId, $action, 'pending', $userId]);
        return (int) DB::conn()->lastInsertId();
    }

    public static function markRunning(int $historyId): void
    {
        DB::conn()->prepare('UPDATE routing_apply_history SET status = ?, started_at = NOW() WHERE id = ?')
            ->execute(['running', $historyId]);
    }

    public static function markSuccess(int $historyId, string $stdout, string $stderr = '', ?string $snapshotDir = null): void
    {
        DB::conn()->prepare('UPDATE routing_apply_history SET status = ?, finished_at = NOW(), stdout = ?, stderr = ?, snapshot_dir = ? WHERE id = ?')
            ->execute(['success', self::maskSecrets($stdout), self::maskSecrets($stderr), $snapshotDir, $historyId]);
    }

    public static function markFailed(int $historyId, string $errorMessage, string $stdout = '', string $stderr = ''): void
    {
        DB::conn()->prepare('UPDATE routing_apply_history SET status = ?, finished_at = NOW(), error_message = ?, stdout = ?, stderr = ? WHERE id = ?')
            ->execute(['failed', $errorMessage, self::maskSecrets($stdout), self::maskSecrets($stderr), $historyId]);
    }

    public static function listByProfile(int $profileId, int $limit = 50): array
    {
        $limit = max(1, min(200, $limit));
        $stmt = DB::conn()->prepare("SELECT * FROM routing_apply_history WHERE profile_id = ? ORDER BY created_at DESC LIMIT {$limit}");
        $stmt->execute([$profileId]);
        return $stmt->fetchAll();
    }

    public static function lastSuccess(int $profileId, string $action = 'apply'): ?array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_apply_history WHERE profile_id = ? AND action = ? AND status = ? ORDER BY created_at DESC LIMIT 1');
        $stmt->execute([$profileId, $action, 'success']);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function findSnapshot(int $profileId, int $serverId, string $snapshotDir): ?array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_apply_history WHERE profile_id = ? AND server_id = ? AND snapshot_dir = ? AND status = ? LIMIT 1');
        $stmt->execute([$profileId, $serverId, $snapshotDir, 'success']);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function maskSecrets(string $text): string
    {
        $text = preg_replace('/(PrivateKey\s*=\s*)\S+/i', '$1[masked]', $text);
        $text = preg_replace('/(PresharedKey\s*=\s*)\S+/i', '$1[masked]', $text);
        return (string) $text;
    }
}
