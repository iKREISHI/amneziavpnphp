<?php

class RoutingScriptBuilder
{
    public function buildApplyScript(array $profile, array $domainRules, array $ipSources, array $manualIps): string
    {
        $p = $this->safeProfile($profile);
        $commands = ['ipset','iptables','ip','dnsmasq','dig','curl','systemctl'];
        $routeTable = $this->routeTable($p);
        $routeLabel = $this->routeTableLabel($p);
        $ruleTablePattern = $this->ruleTablePattern($p);
        $dnsmasqLines = $this->dnsmasqLines($p, $domainRules);
        $warmupDomains = $this->domainList($domainRules);
        $sourceBlocks = '';
        foreach ($ipSources as $source) {
            $target = $this->ipsetName($p, (string) $source['target_ipset']);
            $url = (string) $source['url'];
            $tmp = '/tmp/amnyam-source-' . preg_replace('/[^A-Za-z0-9_-]/', '_', (string) $source['target_ipset']) . '-' . substr(hash('sha1', $url), 0, 12);
            $sourceBlocks .= "\n" . 'curl -fsSL ' . $this->q($url) . ' -o ' . $this->q($tmp) . "\n";
            $sourceBlocks .= "count=0\nwhile read -r net; do\n  [ -z \"\$net\" ] && continue\n  case \"\$net\" in \\#*) continue ;; esac\n  ipset add " . $this->q($target) . " \"\$net\" 2>/dev/null && count=\$((count+1)) || true\ndone < " . $this->q($tmp) . "\necho \"Loaded source " . $this->shText((string) $source['name']) . ": \$count\"\n";
        }
        $manualBlocks = '';
        foreach ($manualIps as $ip) {
            $manualBlocks .= 'ipset add ' . $this->q($this->ipsetName($p, (string) $ip['target_ipset'])) . ' ' . $this->q((string) $ip['value']) . " 2>/dev/null || true\n";
        }
        $dnsmasqConfig = implode("\n", $dnsmasqLines) . "\n";
        $warmup = '';
        foreach ($warmupDomains as $domain) {
            $warmup .= 'dig @127.0.0.1 -p ' . (int) $p['dnsmasq_port'] . ' ' . $this->q(ltrim($domain, '.')) . " A +short >/dev/null || true\n";
        }

        return $this->scriptHeader('set -euo pipefail') . $this->packageBootstrap($commands) . $this->requiredCommands($commands) . "
SNAPSHOT_DIR=" . $this->q(rtrim($p['snapshot_base_dir'], '/')) . "/\$(date +%Y%m%d-%H%M%S)
mkdir -p \"\$SNAPSHOT_DIR\"
iptables-save > \"\$SNAPSHOT_DIR/iptables.rules\" || true
ipset save > \"\$SNAPSHOT_DIR/ipset.rules\" || true
ip rule show > \"\$SNAPSHOT_DIR/iprule.txt\" || true
ip route show table " . $this->q($routeTable) . " > \"\$SNAPSHOT_DIR/route-" . $this->shText($routeLabel) . ".txt\" || true
cp " . $this->q($p['dnsmasq_config_path']) . " \"\$SNAPSHOT_DIR/amnyam-routing.conf\" 2>/dev/null || true
cp /etc/wireguard/" . $this->q($p['upstream_interface'] . '.conf') . " \"\$SNAPSHOT_DIR/" . $this->shText($p['upstream_interface']) . ".conf\" 2>/dev/null || true

ipset create " . $this->q($p['direct_ipset_name']) . " hash:net family inet maxelem 200000 2>/dev/null || true
ipset create " . $this->q($p['upstream_ipset_name']) . " hash:ip family inet timeout 86400 maxelem 200000 2>/dev/null || true
ipset create " . $this->q($p['no_quic_ipset_name']) . " hash:ip family inet timeout 86400 maxelem 200000 2>/dev/null || true
ipset flush " . $this->q($p['direct_ipset_name']) . " || true
ipset flush " . $this->q($p['upstream_ipset_name']) . " || true
ipset flush " . $this->q($p['no_quic_ipset_name']) . " || true
" . $sourceBlocks . $manualBlocks . "
mkdir -p " . $this->q(dirname($p['dnsmasq_config_path'])) . "
cat > " . $this->q($p['dnsmasq_config_path']) . " <<'AMNYAM_DNSMASQ'
" . $dnsmasqConfig . "AMNYAM_DNSMASQ
mkdir -p /root/old-dnsmasq-routing
mv /etc/dnsmasq.d/amn-ru-domains.conf /root/old-dnsmasq-routing/ 2>/dev/null || true
mv /etc/dnsmasq.d/amn-openmail-domains.conf /root/old-dnsmasq-routing/ 2>/dev/null || true
mv /etc/dnsmasq.d/amn-force-niderland.conf /root/old-dnsmasq-routing/ 2>/dev/null || true
mv /etc/dnsmasq.d/amn-no-quic.conf /root/old-dnsmasq-routing/ 2>/dev/null || true
mv /etc/dnsmasq.d/amn-claude.conf /root/old-dnsmasq-routing/ 2>/dev/null || true
dnsmasq --test
systemctl restart dnsmasq

iptables -t mangle -N AMN_TO_AWG 2>/dev/null || true
iptables -t mangle -C PREROUTING -i " . $this->q($p['vpn_input_interface']) . " -j AMN_TO_AWG 2>/dev/null || iptables -t mangle -A PREROUTING -i " . $this->q($p['vpn_input_interface']) . " -j AMN_TO_AWG
iptables -t mangle -F AMN_TO_AWG
for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
  iptables -t mangle -A AMN_TO_AWG -d \"\$net\" -j RETURN
done
iptables -t mangle -A AMN_TO_AWG -m set --match-set " . $this->q($p['upstream_ipset_name']) . " dst -j MARK --set-mark " . $this->q($p['upstream_fwmark']) . "
iptables -t mangle -A AMN_TO_AWG -m set --match-set " . $this->q($p['direct_ipset_name']) . " dst -j RETURN
iptables -t mangle -A AMN_TO_AWG -p tcp -j MARK --set-mark " . $this->q($p['upstream_fwmark']) . "
iptables -C FORWARD -i " . $this->q($p['vpn_input_interface']) . " -p udp --dport 443 -m set --match-set " . $this->q($p['no_quic_ipset_name']) . " dst -j REJECT 2>/dev/null || iptables -I FORWARD 1 -i " . $this->q($p['vpn_input_interface']) . " -p udp --dport 443 -m set --match-set " . $this->q($p['no_quic_ipset_name']) . " dst -j REJECT
ip rule show | grep -Eq \"fwmark " . $this->grepText($p['upstream_fwmark']) . ".*" . $ruleTablePattern . "\" || ip rule add fwmark " . $this->q($p['upstream_fwmark']) . " table " . $this->q($routeTable) . " priority " . (int) $p['upstream_rule_priority'] . "
ip route replace default dev " . $this->q($p['upstream_interface']) . " table " . $this->q($routeTable) . "
" . $warmup . "
ipset save > " . $this->q($p['ipset_persistent_path']) . "
if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save; fi
echo \"AMNyam split routing applied successfully\"
echo \"Snapshot: \$SNAPSHOT_DIR\"
for setname in " . $this->q($p['direct_ipset_name']) . " " . $this->q($p['upstream_ipset_name']) . " " . $this->q($p['no_quic_ipset_name']) . "; do
  echo \"\$setname count:\"
  ipset list \"\$setname\" 2>/dev/null | grep -c \"^[0-9]\" || true
done
echo \"AMN_TO_AWG:\"; iptables -t mangle -L AMN_TO_AWG -n -v --line-numbers || true
echo \"FORWARD no_quic:\"; iptables -S FORWARD | grep " . $this->q($p['no_quic_ipset_name']) . " || true
echo \"IP rules:\"; ip rule show || true
echo \"Route table " . $this->shText($routeLabel) . ":\"; ip route show table " . $this->q($routeTable) . " || true
";
    }

    public function buildUpstreamApplyScript(array $profile, array $upstream): string
    {
        $p = $this->safeProfile($profile);
        $tool = ($upstream['type'] ?? '') === 'wireguard_config' ? 'wg-quick' : 'awg-quick';
        $commands = $tool === 'wg-quick' ? ['ip','wg-quick','systemctl'] : ['ip','systemctl'];
        $routeTable = $this->routeTable($p);
        $ruleTablePattern = $this->ruleTablePattern($p);
        $configB64 = base64_encode((string) $upstream['config_content']);
        $iface = $p['upstream_interface'];
        $toolCheck = $tool === 'awg-quick'
            ? "if ! command -v " . $this->q($tool) . " >/dev/null 2>&1; then echo \"Required command not found: " . $this->shText($tool) . ". Install host AmneziaWG tools, then retry.\" >&2; exit 1; fi\n"
            : '';
        return $this->scriptHeader('set -euo pipefail') . $this->packageBootstrap($commands) . $this->requiredCommands($commands) . "
" . $toolCheck . "mkdir -p /etc/wireguard
umask 077
base64 -d > /etc/wireguard/" . $this->q($iface . '.conf') . " <<'AMNYAM_UPSTREAM_CONF'
" . $configB64 . "
AMNYAM_UPSTREAM_CONF
chmod 600 /etc/wireguard/" . $this->q($iface . '.conf') . "
" . $this->q($tool) . " down " . $this->q($iface) . " 2>/dev/null || true
" . $this->q($tool) . " up " . $this->q($iface) . "
ip link show " . $this->q($iface) . " >/dev/null
ip rule show | grep -Eq \"fwmark " . $this->grepText($p['upstream_fwmark']) . ".*" . $ruleTablePattern . "\" || ip rule add fwmark " . $this->q($p['upstream_fwmark']) . " table " . $this->q($routeTable) . " priority " . (int) $p['upstream_rule_priority'] . "
ip route replace default dev " . $this->q($iface) . " table " . $this->q($routeTable) . "
echo \"Upstream " . $this->shText($iface) . " applied successfully\"
ip addr show " . $this->q($iface) . " || true
wg show " . $this->q($iface) . " 2>/dev/null || awg show " . $this->q($iface) . " 2>/dev/null || true
";
    }

    public function buildWarmupScript(array $profile, array $domainRules): string
    {
        $p = $this->safeProfile($profile);
        $commands = ['dig','ipset'];
        $script = $this->scriptHeader('set -euo pipefail') . $this->packageBootstrap($commands) . $this->requiredCommands($commands);
        foreach ($this->domainList($domainRules) as $domain) {
            $script .= 'dig @127.0.0.1 -p ' . (int) $p['dnsmasq_port'] . ' ' . $this->q(ltrim($domain, '.')) . " A +short >/dev/null || true\n";
        }
        foreach ([$p['direct_ipset_name'], $p['upstream_ipset_name'], $p['no_quic_ipset_name']] as $set) {
            $script .= 'echo ' . $this->q($set . ' count:') . "\nipset list " . $this->q($set) . " 2>/dev/null | grep -c \"^[0-9]\" || true\n";
        }
        return $script;
    }

    public function buildCheckScript(array $profile, string $domain): string
    {
        $p = $this->safeProfile($profile);
        $commands = ['dig','ipset'];
        $domain = strtolower(trim($domain));
        if (!preg_match('/^\.?[a-z0-9][a-z0-9.-]*[a-z0-9]$/i', $domain)) {
            throw new InvalidArgumentException('Invalid domain');
        }
        return $this->scriptHeader('set -euo pipefail') . $this->packageBootstrap($commands) . $this->requiredCommands($commands) . "
d=" . $this->q($domain) . "
ips=\$(dig @127.0.0.1 -p " . (int) $p['dnsmasq_port'] . " +short A \"\$d\" | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort -u)
if [ -z \"\$ips\" ]; then echo \"\$d -> A-records not found\"; exit 1; fi
direct_count=0; nl_count=0; noquic_count=0
for ip in \$ips; do
  if ipset test " . $this->q($p['upstream_ipset_name']) . " \"\$ip\" >/dev/null 2>&1; then nl_count=\$((nl_count+1));
  elif ipset test " . $this->q($p['direct_ipset_name']) . " \"\$ip\" >/dev/null 2>&1; then direct_count=\$((direct_count+1));
  else nl_count=\$((nl_count+1)); fi
  if ipset test " . $this->q($p['no_quic_ipset_name']) . " \"\$ip\" >/dev/null 2>&1; then noquic_count=\$((noquic_count+1)); fi
done
total=\$(echo \"\$ips\" | wc -w)
echo \"\$d\"
echo \"IP: \$(echo \$ips)\"
if [ \"\$direct_count\" -gt 0 ] && [ \"\$nl_count\" -eq 0 ]; then echo \"TCP -> openmail\";
elif [ \"\$nl_count\" -gt 0 ] && [ \"\$direct_count\" -eq 0 ]; then echo \"TCP -> niderland\";
else echo \"TCP -> MIXED: openmail \$direct_count / \$total, niderland \$nl_count / \$total\"; fi
if [ \"\$noquic_count\" -gt 0 ]; then echo \"UDP/443 -> REJECT for \$noquic_count / \$total IP, fallback to TCP\"; else echo \"UDP/443 -> allowed\"; fi
";
    }

    public function buildRollbackScript(array $profile, string $snapshotDir): string
    {
        $p = $this->safeProfile($profile);
        if (!preg_match('#^/root/amnyam-routing-snapshots/[0-9]{8}-[0-9]{6}$#', $snapshotDir)) {
            throw new InvalidArgumentException('Invalid snapshot path');
        }
        return $this->scriptHeader('set -euo pipefail') . "SNAPSHOT_DIR=" . $this->q($snapshotDir) . "
if [ ! -d \"\$SNAPSHOT_DIR\" ]; then echo \"Snapshot directory not found: \$SNAPSHOT_DIR\"; exit 1; fi
if [ -f \"\$SNAPSHOT_DIR/ipset.rules\" ]; then ipset restore < \"\$SNAPSHOT_DIR/ipset.rules\" || true; fi
if [ -f \"\$SNAPSHOT_DIR/iptables.rules\" ]; then iptables-restore < \"\$SNAPSHOT_DIR/iptables.rules\" || true; fi
if [ -f \"\$SNAPSHOT_DIR/amnyam-routing.conf\" ]; then cp \"\$SNAPSHOT_DIR/amnyam-routing.conf\" " . $this->q($p['dnsmasq_config_path']) . "; dnsmasq --test; systemctl restart dnsmasq; fi
if [ -f \"\$SNAPSHOT_DIR/" . $this->shText($p['upstream_interface']) . ".conf\" ]; then cp \"\$SNAPSHOT_DIR/" . $this->shText($p['upstream_interface']) . ".conf\" /etc/wireguard/" . $this->q($p['upstream_interface'] . '.conf') . "; chmod 600 /etc/wireguard/" . $this->q($p['upstream_interface'] . '.conf') . "; fi
if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save; fi
echo \"Rollback completed\"
";
    }

    public function buildStatusScript(array $profile): string
    {
        $p = $this->safeProfile($profile);
        $routeTable = $this->routeTable($p);
        $routeLabel = $this->routeTableLabel($p);
        $ruleTablePattern = $this->ruleTablePattern($p);
        return $this->scriptHeader('set -uo pipefail') . "
for setname in " . $this->q($p['direct_ipset_name']) . " " . $this->q($p['upstream_ipset_name']) . " " . $this->q($p['no_quic_ipset_name']) . "; do
  if ipset list \"\$setname\" >/dev/null 2>&1; then echo \"ipset \$setname: exists count=\$(ipset list \"\$setname\" | grep -c '^[0-9]' || true)\"; else echo \"ipset \$setname: missing\"; fi
done
iptables -t mangle -L AMN_TO_AWG -n >/dev/null 2>&1 && echo \"chain AMN_TO_AWG: exists\" || echo \"chain AMN_TO_AWG: missing\"
iptables -t mangle -C PREROUTING -i " . $this->q($p['vpn_input_interface']) . " -j AMN_TO_AWG 2>/dev/null && echo \"prerouting hook: yes\" || echo \"prerouting hook: no\"
iptables -S FORWARD | grep -q " . $this->q($p['no_quic_ipset_name']) . " && echo \"no_quic forward: yes\" || echo \"no_quic forward: no\"
ip rule show | grep -Eq \"fwmark " . $this->grepText($p['upstream_fwmark']) . ".*" . $ruleTablePattern . "\" && echo \"ip rule: yes\" || echo \"ip rule: no\"
ip route show table " . $this->q($routeTable) . " | grep -q \"default dev " . $this->grepText($p['upstream_interface']) . "\" && echo \"route table " . $this->shText($routeLabel) . ": default yes\" || echo \"route table " . $this->shText($routeLabel) . ": default no\"
systemctl is-active dnsmasq 2>/dev/null | sed 's/^/dnsmasq: /' || echo \"dnsmasq: unknown\"
ip link show " . $this->q($p['upstream_interface']) . " >/dev/null 2>&1 && echo \"upstream link " . $this->shText($p['upstream_interface']) . ": exists\" || echo \"upstream link " . $this->shText($p['upstream_interface']) . ": missing\"
wg show " . $this->q($p['upstream_interface']) . " 2>/dev/null || awg show " . $this->q($p['upstream_interface']) . " 2>/dev/null || true
";
    }

    public function buildUpstreamTestScript(array $profile): string
    {
        $p = $this->safeProfile($profile);
        return $this->scriptHeader('set -uo pipefail') . "
ip link show " . $this->q($p['upstream_interface']) . " >/dev/null 2>&1 && echo \"link: up\" || { echo \"link: missing\"; exit 1; }
ip route get 1.1.1.1 mark " . $this->q($p['upstream_fwmark']) . " 2>/dev/null || true
wg show " . $this->q($p['upstream_interface']) . " 2>/dev/null || awg show " . $this->q($p['upstream_interface']) . " 2>/dev/null || true
";
    }

    private function dnsmasqLines(array $p, array $rules): array
    {
        $lines = [];
        foreach ($rules as $rule) {
            if (empty($rule['enabled'])) {
                continue;
            }
            $sets = [];
            if (!empty($rule['add_to_direct'])) {
                $sets[] = $p['direct_ipset_name'];
            }
            if (!empty($rule['add_to_upstream'])) {
                $sets[] = $p['upstream_ipset_name'];
            }
            if (!empty($rule['add_to_no_quic'])) {
                $sets[] = $p['no_quic_ipset_name'];
            }
            if (!$sets) {
                continue;
            }
            $domain = (string) $rule['domain'];
            $lines[] = 'ipset=/' . $domain . '/' . implode(',', $sets);
        }
        return $lines;
    }

    private function domainList(array $rules): array
    {
        $domains = [];
        foreach ($rules as $rule) {
            if (!empty($rule['enabled'])) {
                $domains[] = (string) $rule['domain'];
            }
        }
        return array_values(array_unique($domains));
    }

    private function safeProfile(array $profile): array
    {
        foreach (['direct_ipset_name','upstream_ipset_name','no_quic_ipset_name','upstream_interface','upstream_table_name','vpn_input_interface'] as $field) {
            RoutingProfile::validateIdentifier((string) $profile[$field], $field);
        }
        $tableId = (int) ($profile['upstream_table_id'] ?? 0);
        if ($tableId < 1 || $tableId > 2147483647) {
            throw new InvalidArgumentException('Invalid upstream_table_id');
        }
        if (!preg_match('/^0x[0-9a-fA-F]+$/', (string) $profile['upstream_fwmark'])) {
            throw new InvalidArgumentException('Invalid fwmark');
        }
        return $profile;
    }

    private function ipsetName(array $p, string $target): string
    {
        return match ($target) {
            'direct_ip' => $p['direct_ipset_name'],
            'niderland_ip' => $p['upstream_ipset_name'],
            'no_quic' => $p['no_quic_ipset_name'],
            default => throw new InvalidArgumentException('Invalid ipset target'),
        };
    }

    private function requiredCommands(array $commands): string
    {
        $script = '';
        foreach ($commands as $cmd) {
            $script .= 'command -v ' . $this->q($cmd) . ' >/dev/null 2>&1 || { echo "Required command not found: ' . $this->shText($cmd) . "\" >&2; exit 1; }\n";
        }
        return $script;
    }

    private function scriptHeader(string $setFlags): string
    {
        return "#!/bin/bash\n" . $setFlags . "\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH\n";
    }

    private function packageBootstrap(array $commands): string
    {
        $packages = [
            'apt' => [
                'ipset' => 'ipset',
                'iptables' => 'iptables',
                'ip' => 'iproute2',
                'dnsmasq' => 'dnsmasq',
                'dig' => 'dnsutils',
                'curl' => 'curl',
                'wg-quick' => 'wireguard-tools',
            ],
            'dnf' => [
                'ipset' => 'ipset',
                'iptables' => 'iptables',
                'ip' => 'iproute',
                'dnsmasq' => 'dnsmasq',
                'dig' => 'bind-utils',
                'curl' => 'curl',
                'wg-quick' => 'wireguard-tools',
            ],
            'yum' => [
                'ipset' => 'ipset',
                'iptables' => 'iptables',
                'ip' => 'iproute',
                'dnsmasq' => 'dnsmasq',
                'dig' => 'bind-utils',
                'curl' => 'curl',
                'wg-quick' => 'wireguard-tools',
            ],
            'apk' => [
                'ipset' => 'ipset',
                'iptables' => 'iptables',
                'ip' => 'iproute2',
                'dnsmasq' => 'dnsmasq',
                'dig' => 'bind-tools',
                'curl' => 'curl',
                'wg-quick' => 'wireguard-tools',
            ],
        ];

        $install = [];
        foreach ($packages as $manager => $map) {
            $install[$manager] = [];
            foreach ($commands as $command) {
                if (isset($map[$command])) {
                    $install[$manager][] = $map[$command];
                }
            }
            $install[$manager] = array_values(array_unique($install[$manager]));
        }

        if (!$install['apt'] && !$install['dnf'] && !$install['yum'] && !$install['apk']) {
            return '';
        }

        $commandList = implode(' ', array_map([$this, 'q'], $commands));
        $missingList = implode(' ', array_map([$this, 'shText'], $commands));

        return "AMNYAM_MISSING=0\nfor cmd in " . $commandList . "; do\n  command -v \"\$cmd\" >/dev/null 2>&1 || AMNYAM_MISSING=1\ndone\nif [ \"\$AMNYAM_MISSING\" -ne 0 ]; then\n  if command -v apt-get >/dev/null 2>&1; then\n    export DEBIAN_FRONTEND=noninteractive\n    apt-get update -qq\n    apt-get install -y -qq " . implode(' ', array_map([$this, 'q'], $install['apt'])) . "\n  elif command -v dnf >/dev/null 2>&1; then\n    dnf install -y " . implode(' ', array_map([$this, 'q'], $install['dnf'])) . "\n  elif command -v yum >/dev/null 2>&1; then\n    yum install -y " . implode(' ', array_map([$this, 'q'], $install['yum'])) . "\n  elif command -v apk >/dev/null 2>&1; then\n    apk add --no-cache " . implode(' ', array_map([$this, 'q'], $install['apk'])) . "\n  else\n    echo \"Required command(s) missing and no supported package manager found: " . $missingList . "\" >&2\n  fi\nfi\n";
    }

    private function routeTable(array $p): string
    {
        return (string) (int) $p['upstream_table_id'];
    }

    private function routeTableLabel(array $p): string
    {
        return $p['upstream_table_name'] . ' (' . $this->routeTable($p) . ')';
    }

    private function ruleTablePattern(array $p): string
    {
        return '(lookup )?(' . $this->grepText($p['upstream_table_name']) . '|' . $this->grepText($this->routeTable($p)) . ')([[:space:]]|$)';
    }

    private function q(string $value): string
    {
        return escapeshellarg($value);
    }

    private function shText(string $value): string
    {
        return str_replace(["\n", "\r"], ' ', $value);
    }

    private function grepText(string $value): string
    {
        return preg_quote($value, '/');
    }
}
