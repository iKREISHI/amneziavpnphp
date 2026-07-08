<?php

class RoutingService
{
    private RoutingScriptBuilder $builder;

    public function __construct()
    {
        $this->builder = new RoutingScriptBuilder();
    }

    public function contextForServer(int $serverId): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        return [
            'profile' => $profile,
            'rules' => RoutingRule::listByProfile((int) $profile['id']),
            'sources' => RoutingIpSource::listByProfile((int) $profile['id']),
            'manual_ips' => RoutingManualIp::listByProfile((int) $profile['id']),
            'upstream' => RoutingUpstream::getActiveByProfile((int) $profile['id']),
            'history' => RoutingApplyHistory::listByProfile((int) $profile['id'], 10),
            'last_apply' => RoutingApplyHistory::lastSuccess((int) $profile['id'], 'apply'),
        ];
    }

    public function apply(int $serverId, ?int $userId = null): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        $upstream = RoutingUpstream::getActiveByProfile((int) $profile['id']);
        if (!$upstream) {
            throw new RuntimeException('Active niderland upstream is not configured');
        }
        $historyId = RoutingApplyHistory::create((int) $profile['id'], $serverId, 'apply', $userId);
        return $this->runHistoryScript($serverId, $historyId, $this->builder->buildApplyScript(
            $profile,
            RoutingRule::listEnabledByProfile((int) $profile['id']),
            RoutingIpSource::listEnabledByProfile((int) $profile['id']),
            RoutingManualIp::listEnabledByProfile((int) $profile['id'])
        ));
    }

    public function warmup(int $serverId, ?int $userId = null): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        $historyId = RoutingApplyHistory::create((int) $profile['id'], $serverId, 'warmup', $userId);
        return $this->runHistoryScript($serverId, $historyId, $this->builder->buildWarmupScript($profile, RoutingRule::listEnabledByProfile((int) $profile['id'])));
    }

    public function check(int $serverId, string $domain, ?int $userId = null): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        $historyId = RoutingApplyHistory::create((int) $profile['id'], $serverId, 'check', $userId);
        DB::conn()->prepare('UPDATE routing_apply_history SET domain_checked = ? WHERE id = ?')->execute([$domain, $historyId]);
        return $this->runHistoryScript($serverId, $historyId, $this->builder->buildCheckScript($profile, $domain));
    }

    public function status(int $serverId): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        $result = (new VpnServer($serverId))->runRemoteScript($this->builder->buildStatusScript($profile));
        $result['rows'] = RoutingDiagnostics::parseStatusOutput($result['stdout'] ?? '');
        $result['last_apply'] = RoutingApplyHistory::lastSuccess((int) $profile['id'], 'apply');
        return $result;
    }

    public function rollback(int $serverId, string $snapshotDir, ?int $userId = null): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        if (!preg_match('#^/root/amnyam-routing-snapshots/[0-9]{8}-[0-9]{6}$#', $snapshotDir)) {
            throw new InvalidArgumentException('Invalid snapshot directory');
        }
        if (!RoutingApplyHistory::findSnapshot((int) $profile['id'], $serverId, $snapshotDir)) {
            throw new InvalidArgumentException('Snapshot is not registered for this server');
        }
        $historyId = RoutingApplyHistory::create((int) $profile['id'], $serverId, 'rollback', $userId);
        return $this->runHistoryScript($serverId, $historyId, $this->builder->buildRollbackScript($profile, $snapshotDir));
    }

    public function importUpstream(int $serverId, string $config, string $name = 'niderland'): int
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        return RoutingUpstream::saveImported((int) $profile['id'], $serverId, [
            'name' => $name,
            'config_content' => $config,
        ]);
    }

    public function applyUpstream(int $serverId, ?int $userId = null): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        $upstream = RoutingUpstream::getActiveByProfile((int) $profile['id']);
        if (!$upstream) {
            throw new RuntimeException('Active niderland upstream is not configured');
        }
        $historyId = RoutingApplyHistory::create((int) $profile['id'], $serverId, 'upstream_apply', $userId);
        $result = $this->runHistoryScript($serverId, $historyId, $this->builder->buildUpstreamApplyScript($profile, $upstream));
        RoutingUpstream::markApplied((int) $upstream['id'], (int) $result['exit_code'] === 0, (int) $result['exit_code'] === 0 ? null : ($result['stderr'] ?: $result['stdout']));
        return $result;
    }

    public function testUpstream(int $serverId, ?int $userId = null): array
    {
        $profile = RoutingProfile::getOrCreateForServer($serverId);
        $historyId = RoutingApplyHistory::create((int) $profile['id'], $serverId, 'upstream_test', $userId);
        return $this->runHistoryScript($serverId, $historyId, $this->builder->buildUpstreamTestScript($profile));
    }

    private function runHistoryScript(int $serverId, int $historyId, string $script): array
    {
        RoutingApplyHistory::markRunning($historyId);
        $result = (new VpnServer($serverId))->runRemoteScript($script);
        $snapshot = null;
        if (preg_match('/^Snapshot:\s*(.+)$/m', $result['stdout'] ?? '', $m)) {
            $snapshot = trim($m[1]);
        }
        if ((int) ($result['exit_code'] ?? 1) === 0) {
            RoutingApplyHistory::markSuccess($historyId, $result['stdout'] ?? '', $result['stderr'] ?? '', $snapshot);
        } else {
            RoutingApplyHistory::markFailed($historyId, trim(($result['stderr'] ?? '') ?: ($result['stdout'] ?? 'Remote script failed')), $result['stdout'] ?? '', $result['stderr'] ?? '');
        }
        return $result + ['history_id' => $historyId, 'snapshot_dir' => $snapshot];
    }
}
