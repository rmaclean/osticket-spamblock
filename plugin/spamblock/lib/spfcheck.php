<?php

class SpamblockSpfCheckProvider implements SpamblockSpamCheckProvider
{
    private const MAX_DEPTH = 8;

    public function getName()
    {
        return 'spf';
    }

    public function check(SpamblockEmailContext $context)
    {
        $email = trim((string) $context->getFromEmail());
        $ip = trim((string) $context->getIp());

        $domain = '';
        if (substr_count($email, '@') === 1) {
            $parts = explode('@', $email, 2);
            $domain = strtolower(trim($parts[1] ?? ''));
        }

        if ($domain === '' || !preg_match('/^[a-z0-9.-]+$/', $domain)) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to determine sender domain for SPF check',
                null,
                [
                    'result' => 'invalid',
                    'domain' => $domain,
                    'ip' => $ip,
                ]
            );
        }

        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'No valid IP address available for SPF check',
                null,
                [
                    'result' => 'invalid',
                    'domain' => $domain,
                    'ip' => $ip,
                ]
            );
        }

        $trace = [];
        $res = $this->evaluateDomain($domain, $ip, 0, $trace);

        return new SpamblockSpamCheckResult(
            $this->getName(),
            null,
            $res['error'],
            null,
            [
                'result' => $res['result'],
                'domain' => $domain,
                'evaluated_domain' => $res['domain'],
                'redirect_chain' => $res['redirect_chain'],
                'ip' => $ip,
                'record' => $res['record'],
                'raw' => $res['raw'],
                'trace' => $trace,
            ]
        );
    }

    private function evaluateDomain($domain, $ip, $depth, &$trace = null)
    {
        if (!is_array($trace)) {
            $trace = [];
        }

        if ($depth >= self::MAX_DEPTH) {
            $trace[] = sprintf('domain=%s depth=%s error=%s', $domain, $depth, 'SPF recursion limit exceeded');

            return [
                'domain' => $domain,
                'result' => 'invalid',
                'raw' => 'permerror',
                'record' => null,
                'redirect_chain' => [],
                'error' => 'SPF recursion limit exceeded',
            ];
        }

        $recordInfo = $this->getSpfRecord($domain);
        if ($recordInfo['error']) {
            $trace[] = sprintf(
                'domain=%s spf_record=%s raw=%s result=%s error=%s',
                $domain,
                $recordInfo['record'] !== null ? (string) $recordInfo['record'] : '(none)',
                'temperror',
                'invalid',
                $recordInfo['error']
            );

            return [
                'domain' => $domain,
                'result' => 'invalid',
                'raw' => 'temperror',
                'record' => $recordInfo['record'],
                'redirect_chain' => [],
                'error' => $recordInfo['error'],
            ];
        }

        $record = $recordInfo['record'];
        if ($record === null) {
            $trace[] = sprintf('domain=%s spf_record=%s raw=%s result=%s', $domain, '(none)', 'none', 'none');

            return [
                'domain' => $domain,
                'result' => 'none',
                'raw' => 'none',
                'record' => null,
                'redirect_chain' => [],
                'error' => null,
            ];
        }

        $trace[] = sprintf('domain=%s spf_record=%s', $domain, $record);

        $eval = $this->evaluateRecord($domain, $ip, $record, $depth, $trace);

        $trace[] = sprintf(
            'domain=%s raw=%s result=%s%s',
            array_key_exists('domain', $eval) ? (string) $eval['domain'] : $domain,
            (string) $eval['raw'],
            (string) $eval['result'],
            array_key_exists('redirect_chain', $eval) && is_array($eval['redirect_chain']) && $eval['redirect_chain']
                ? (' redirect_chain=' . implode('->', $eval['redirect_chain']))
                : ''
        );

        return [
            'domain' => array_key_exists('domain', $eval) ? $eval['domain'] : $domain,
            'result' => $eval['result'],
            'raw' => $eval['raw'],
            'record' => array_key_exists('record', $eval) ? $eval['record'] : $record,
            'redirect_chain' => array_key_exists('redirect_chain', $eval) ? $eval['redirect_chain'] : [],
            'error' => $eval['error'],
        ];
    }

    private function getSpfRecord($domain)
    {
        if (!function_exists('dns_get_record')) {
            return [
                'record' => null,
                'error' => 'dns_get_record is unavailable',
            ];
        }

        $records = @dns_get_record($domain, DNS_TXT);
        if ($records === false) {
            return [
                'record' => null,
                'error' => 'DNS TXT lookup failed',
            ];
        }

        $spf = [];
        foreach ($records as $r) {
            if (!is_array($r) || !isset($r['txt'])) {
                continue;
            }

            $txt = trim((string) $r['txt']);
            if (stripos($txt, 'v=spf1') === 0) {
                $spf[] = $txt;
            }
        }

        if (!$spf) {
            return [
                'record' => null,
                'error' => null,
            ];
        }

        if (count($spf) > 1) {
            return [
                'record' => null,
                'error' => 'Multiple SPF records found',
            ];
        }

        return [
            'record' => $spf[0],
            'error' => null,
        ];
    }

    private function evaluateRecord($domain, $ip, $record, $depth, &$trace = null)
    {
        if (!is_array($trace)) {
            $trace = [];
        }
        $record = trim((string) $record);
        if (stripos($record, 'v=spf1') !== 0) {
            return [
                'result' => 'invalid',
                'raw' => 'permerror',
                'error' => 'Invalid SPF record',
            ];
        }

        $tokens = preg_split('/\s+/', $record);
        if (!$tokens) {
            return [
                'result' => 'invalid',
                'raw' => 'permerror',
                'error' => 'Unable to parse SPF record',
            ];
        }

        $redirect = null;
        $matched = null;
        $matchedBy = null;

        foreach ($tokens as $t) {
            $t = trim((string) $t);
            if ($t === '' || strcasecmp($t, 'v=spf1') === 0) {
                continue;
            }

            if (stripos($t, 'redirect=') === 0) {
                $redirect = substr($t, strlen('redirect='));
                continue;
            }

            $qual = '+';
            $first = substr($t, 0, 1);
            if (in_array($first, ['+', '-', '~', '?'], true)) {
                $qual = $first;
                $t = substr($t, 1);
            }

            if ($t === 'all') {
                $matched = $qual;
                $matchedBy = 'all';
                break;
            }

            if (stripos($t, 'ip4:') === 0) {
                $cidr = substr($t, strlen('ip4:'));
                if ($this->cidrMatch($ip, $cidr)) {
                    $matched = $qual;
                    $matchedBy = 'ip4:' . $cidr;
                    break;
                }
                continue;
            }

            if (stripos($t, 'ip6:') === 0) {
                $cidr = substr($t, strlen('ip6:'));
                if ($this->cidrMatch($ip, $cidr)) {
                    $matched = $qual;
                    $matchedBy = 'ip6:' . $cidr;
                    break;
                }
                continue;
            }

            if (stripos($t, 'include:') === 0) {
                $includeDomain = substr($t, strlen('include:'));
                $includeDomain = strtolower(trim($includeDomain));
                if ($includeDomain === '') {
                    return [
                        'result' => 'invalid',
                        'raw' => 'permerror',
                        'error' => 'Invalid include mechanism',
                    ];
                }

                $trace[] = sprintf('domain=%s include=%s', $domain, $includeDomain);
                $included = $this->evaluateDomain($includeDomain, $ip, $depth + 1, $trace);
                if ($included['raw'] === 'pass') {
                    $matched = $qual;
                    $matchedBy = 'include:' . $includeDomain;
                    break;
                }

                continue;
            }

            if ($t === 'a' || stripos($t, 'a:') === 0) {
                $aDomain = $t === 'a' ? $domain : substr($t, strlen('a:'));
                $aDomain = strtolower(trim($aDomain));
                if ($this->domainHasIp($aDomain, $ip)) {
                    $matched = $qual;
                    $matchedBy = ($t === 'a') ? 'a' : ('a:' . $aDomain);
                    break;
                }
                continue;
            }

            if ($t === 'mx' || stripos($t, 'mx:') === 0) {
                $mxDomain = $t === 'mx' ? $domain : substr($t, strlen('mx:'));
                $mxDomain = strtolower(trim($mxDomain));
                if ($this->mxHasIp($mxDomain, $ip)) {
                    $matched = $qual;
                    $matchedBy = ($t === 'mx') ? 'mx' : ('mx:' . $mxDomain);
                    break;
                }
                continue;
            }

            $trace[] = sprintf('domain=%s unsupported_mechanism=%s', $domain, $t);

            return [
                'result' => 'invalid',
                'raw' => 'permerror',
                'error' => 'Unsupported SPF mechanism: ' . $t,
            ];
        }

        if ($matched === null && $redirect) {
            $redirect = strtolower(trim((string) $redirect));
            if ($redirect === '') {
                return [
                    'result' => 'invalid',
                    'raw' => 'permerror',
                    'error' => 'Invalid redirect modifier',
                ];
            }

            $trace[] = sprintf('domain=%s redirect=%s', $domain, $redirect);
            $redir = $this->evaluateDomain($redirect, $ip, $depth + 1, $trace);

            $chain = [$redirect];
            if (isset($redir['redirect_chain']) && is_array($redir['redirect_chain']) && $redir['redirect_chain']) {
                $chain = array_merge($chain, $redir['redirect_chain']);
            }

            return [
                'domain' => $redir['domain'],
                'record' => $redir['record'],
                'redirect_chain' => $chain,
                'result' => $redir['result'],
                'raw' => $redir['raw'],
                'error' => $redir['error'],
            ];
        }

        $raw = 'neutral';
        if ($matched === '+') {
            $raw = 'pass';
        } elseif ($matched === '-') {
            $raw = 'fail';
        } elseif ($matched === '~') {
            $raw = 'softfail';
        } elseif ($matched === '?') {
            $raw = 'neutral';
        }

        if ($matchedBy !== null) {
            $trace[] = sprintf('domain=%s matched=%s qualifier=%s raw=%s', $domain, $matchedBy, $matched, $raw);
        }

        $simplified = $raw;
        if ($raw === 'pass' || $raw === 'neutral') {
            $simplified = 'pass';
        } elseif ($raw === 'fail' || $raw === 'softfail') {
            $simplified = 'fail';
        }

        return [
            'result' => $simplified,
            'raw' => $raw,
            'error' => null,
        ];
    }

    private function domainHasIp($domain, $ip)
    {
        if ($domain === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $type = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? DNS_AAAA : DNS_A;
        $records = @dns_get_record($domain, $type);
        if ($records === false) {
            return false;
        }

        foreach ($records as $r) {
            if (!is_array($r)) {
                continue;
            }

            $candidate = $type === DNS_AAAA ? ($r['ipv6'] ?? null) : ($r['ip'] ?? null);
            if ($candidate && trim((string) $candidate) === $ip) {
                return true;
            }
        }

        return false;
    }

    private function mxHasIp($domain, $ip)
    {
        if ($domain === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $mx = @dns_get_record($domain, DNS_MX);
        if ($mx === false || !$mx) {
            return false;
        }

        foreach ($mx as $r) {
            if (!is_array($r) || empty($r['target'])) {
                continue;
            }

            if ($this->domainHasIp((string) $r['target'], $ip)) {
                return true;
            }
        }

        return false;
    }

    private function cidrMatch($ip, $cidr)
    {
        $ip = trim((string) $ip);
        $cidr = trim((string) $cidr);

        if ($ip === '' || $cidr === '') {
            return false;
        }

        if (strpos($cidr, '/') === false) {
            $cidr = $cidr . (filter_var($cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '/128' : '/32');
        }

        [$subnet, $mask] = explode('/', $cidr, 2);
        $mask = (int) $mask;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ipBin = @inet_pton($ip);
            $subBin = @inet_pton($subnet);
            if ($ipBin === false || $subBin === false) {
                return false;
            }

            return $this->matchBits($ipBin, $subBin, $mask, 128);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $subLong = ip2long($subnet);
            if ($ipLong === false || $subLong === false) {
                return false;
            }

            if ($mask < 0 || $mask > 32) {
                return false;
            }

            $maskLong = $mask === 0 ? 0 : (-1 << (32 - $mask));
            return (($ipLong & $maskLong) === ($subLong & $maskLong));
        }

        return false;
    }

    private function matchBits($ipBin, $subBin, $mask, $max)
    {
        if ($mask < 0 || $mask > $max) {
            return false;
        }

        $bytes = (int) floor($mask / 8);
        $bits = $mask % 8;

        if ($bytes) {
            if (substr($ipBin, 0, $bytes) !== substr($subBin, 0, $bytes)) {
                return false;
            }
        }

        if ($bits === 0) {
            return true;
        }

        $ipByte = ord($ipBin[$bytes]);
        $subByte = ord($subBin[$bytes]);
        $maskByte = 0xFF << (8 - $bits);

        return (($ipByte & $maskByte) === ($subByte & $maskByte));
    }
}
