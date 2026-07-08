<?php

class RoutingProfile
{
    public static function getOrCreateForServer(int $serverId): array
    {
        $profile = self::getActiveForServer($serverId);
        if ($profile) {
            self::seedDefaults((int) $profile['id']);
            return $profile;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('INSERT INTO routing_profiles (server_id, name, description, is_active) VALUES (?, ?, ?, 1)');
        $stmt->execute([$serverId, 'default', 'Default split routing profile']);
        $profileId = (int) $pdo->lastInsertId();
        self::seedDefaults($profileId);

        return self::find($profileId);
    }

    public static function getActiveForServer(int $serverId): ?array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_profiles WHERE server_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1');
        $stmt->execute([$serverId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function find(int $profileId): ?array
    {
        $stmt = DB::conn()->prepare('SELECT * FROM routing_profiles WHERE id = ? LIMIT 1');
        $stmt->execute([$profileId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function update(int $profileId, array $data): void
    {
        $allowed = [
            'name', 'description', 'direct_ipset_name', 'upstream_ipset_name', 'no_quic_ipset_name',
            'direct_route_name', 'upstream_route_name', 'upstream_interface', 'upstream_table_name',
            'upstream_table_id', 'upstream_fwmark', 'upstream_rule_priority', 'vpn_input_interface',
            'dnsmasq_port', 'dnsmasq_config_path', 'ipset_persistent_path', 'snapshot_base_dir',
            'enabled',
        ];
        $set = [];
        $params = [];
        foreach ($allowed as $key) {
            if (!array_key_exists($key, $data)) {
                continue;
            }
            $value = $data[$key];
            if (in_array($key, ['direct_ipset_name', 'upstream_ipset_name', 'no_quic_ipset_name', 'upstream_interface', 'upstream_table_name', 'vpn_input_interface'], true)) {
                self::validateIdentifier((string) $value, $key);
            }
            if ($key === 'upstream_table_id' && ((int) $value < 1 || (int) $value > 2147483647)) {
                throw new InvalidArgumentException('Invalid upstream_table_id');
            }
            if ($key === 'upstream_fwmark' && !preg_match('/^0x[0-9a-fA-F]+$/', (string) $value)) {
                throw new InvalidArgumentException('Invalid fwmark');
            }
            $set[] = $key . ' = ?';
            $params[] = $value;
        }
        if (!$set) {
            return;
        }
        $params[] = $profileId;
        DB::conn()->prepare('UPDATE routing_profiles SET ' . implode(', ', $set) . ' WHERE id = ?')->execute($params);
    }

    public static function validateIdentifier(string $value, string $field = 'identifier'): void
    {
        if (!preg_match('/^[A-Za-z0-9_.:-]{1,64}$/', $value)) {
            throw new InvalidArgumentException("Invalid {$field}");
        }
    }

    private static function seedDefaults(int $profileId): void
    {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT id FROM routing_ip_sources WHERE profile_id = ? AND name = ? LIMIT 1');
        $stmt->execute([$profileId, 'RU IP ranges']);
        if (!$stmt->fetchColumn()) {
            RoutingIpSource::create($profileId, [
                'name' => 'RU IP ranges',
                'target_ipset' => 'direct_ip',
                'source_type' => 'url_cidr_list',
                'url' => 'https://www.ipdeny.com/ipblocks/data/countries/ru.zone',
                'enabled' => 1,
                'refresh_interval_seconds' => 86400,
            ]);
        }

        foreach (self::defaultRules() as $rule) {
            $stmt = $pdo->prepare('SELECT id FROM routing_domain_rules WHERE profile_id = ? AND domain = ? AND match_type = ? LIMIT 1');
            $stmt->execute([$profileId, $rule['domain'], $rule['match_type']]);
            if (!$stmt->fetchColumn()) {
                RoutingRule::create($profileId, $rule);
            }
        }
    }

    private static function defaultRules(): array
    {
        $direct = ['.ru','yandex.ru','ya.ru','vk.com','mail.ru','ok.ru','avito.ru','ozon.ru','ozon.com','cdn-ozon.ru','ozonusercontent.com','wildberries.ru','sberbank.ru','tbank.ru','tinkoff.ru','gosuslugi.ru','max.ru','web.max.ru','st.max.ru','platform-api.max.ru','oneme.ru','api.oneme.ru','i.oneme.ru','ws-api.oneme.ru','apptracer.ru','sdk-api.apptracer.ru','okcdn.ru','calls.okcdn.ru','iv.okcdn.ru','api.ipify.org','checkip.amazonaws.com','ifconfig.me','icanhazip.com','ident.me','ipinfo.io'];
        $upstreamNoQuic = ['claude.com','claude.ai','anthropic.com','api.anthropic.com','console.anthropic.com'];
        $upstream = ['pornhub.ru','www.pornhub.ru','pornhub.org','rt.pornhub.org'];
        $noQuic = ['tiktok.com','www.tiktok.com','m.tiktok.com','tiktokv.com','tiktokcdn.com','tiktokcdn-us.com','musical.ly','muscdn.com','byteoversea.com','bytefcdn-oversea.com','bytedance.com','byteimg.com','ibyteimg.com','ibytedtos.com','snssdk.com','pstatp.com'];
        $rules = [];
        foreach ($direct as $d) {
            $rules[] = ['domain' => $d, 'match_type' => $d === '.ru' ? 'suffix' : 'suffix', 'add_to_direct' => 1, 'add_to_upstream' => 0, 'add_to_no_quic' => 0, 'enabled' => 1, 'priority' => 100, 'comment' => 'Default direct/openmail'];
        }
        foreach ($upstreamNoQuic as $d) {
            $rules[] = ['domain' => $d, 'match_type' => 'suffix', 'add_to_direct' => 0, 'add_to_upstream' => 1, 'add_to_no_quic' => 1, 'enabled' => 1, 'priority' => 100, 'comment' => 'Default niderland + No QUIC'];
        }
        foreach ($upstream as $d) {
            $rules[] = ['domain' => $d, 'match_type' => 'suffix', 'add_to_direct' => 0, 'add_to_upstream' => 1, 'add_to_no_quic' => 0, 'enabled' => 1, 'priority' => 100, 'comment' => 'Default niderland'];
        }
        foreach ($noQuic as $d) {
            $rules[] = ['domain' => $d, 'match_type' => 'suffix', 'add_to_direct' => 0, 'add_to_upstream' => 0, 'add_to_no_quic' => 1, 'enabled' => 1, 'priority' => 100, 'comment' => 'Default No QUIC'];
        }
        return $rules;
    }
}
