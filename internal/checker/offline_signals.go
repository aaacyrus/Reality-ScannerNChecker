package checker

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	cruxSnapshot    = "202606"
	cruxBloomBits   = uint64(2_879_003)
	cruxBloomHashes = uint64(20)
	cruxBloomCount  = 99_946
	cdnSnapshot     = "20260723"
)

var (
	cruxFreshUntil        = time.Date(2026, time.September, 12, 23, 59, 59, 0, time.UTC)
	cdnNegativeFreshUntil = time.Date(2026, time.August, 3, 23, 59, 59, 0, time.UTC)
)

// Derived from the Chrome UX Report global Top 100k for 202606 (CC BY 4.0).
// See THIRD_PARTY_NOTICES.md for source, transformation, and checksum details.
//
//go:embed data/crux_top_100k_202606.bin
var cruxBloom []byte

type cdnEvidence struct {
	layer    uint8
	provider string
	detail   string
}

type cdnFinding struct {
	known      bool
	detected   bool
	provider   string
	confidence string
	evidence   string
}

const (
	cdnLayerDNS uint8 = 1 << iota
	cdnLayerIP
	cdnLayerHTTP
)

func classifyPopularity(hosts []string, now time.Time) (known, hot bool, match string) {
	seen := make(map[string]struct{}, len(hosts))
	for _, raw := range hosts {
		host := normalizeDomain(raw)
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		if cruxBloomContains(host) {
			return true, true, host
		}
	}
	if !now.After(cruxFreshUntil) {
		return true, false, ""
	}
	return false, false, ""
}

func cruxBloomContains(host string) bool {
	host = normalizeDomain(host)
	if host == "" {
		return false
	}
	digest := sha256.Sum256([]byte(host))
	first := binary.LittleEndian.Uint64(digest[:8]) % cruxBloomBits
	step := binary.LittleEndian.Uint64(digest[8:16]) % cruxBloomBits
	if step == 0 {
		step = 1
	}
	for index := uint64(0); index < cruxBloomHashes; index++ {
		bit := (first + index*step) % cruxBloomBits
		if cruxBloom[bit/8]&(1<<uint(bit%8)) == 0 {
			return false
		}
	}
	return true
}

func classifyCDN(observations []cdnEvidence, successfulRounds int, cnameChecked bool, now time.Time) cdnFinding {
	providers := make([]string, 0, 2)
	details := make([]string, 0, len(observations))
	providerSeen := make(map[string]struct{})
	detailSeen := make(map[string]struct{})
	var layers uint8
	for _, observation := range observations {
		if observation.provider == "" {
			continue
		}
		layers |= observation.layer
		if _, exists := providerSeen[observation.provider]; !exists {
			providerSeen[observation.provider] = struct{}{}
			providers = append(providers, observation.provider)
		}
		if observation.detail != "" {
			if _, exists := detailSeen[observation.detail]; !exists {
				detailSeen[observation.detail] = struct{}{}
				details = append(details, observation.detail)
			}
		}
	}
	if len(providers) > 0 {
		provider := providers[0]
		if len(providers) > 1 {
			provider = "Multiple"
		}
		confidence := "medium"
		if now.After(cdnNegativeFreshUntil) && layers == cdnLayerIP {
			confidence = "low"
		} else if len(providers) > 1 {
			confidence = "high"
		} else if layers&(layers-1) != 0 {
			confidence = "high"
		}
		return cdnFinding{known: true, detected: true, provider: provider, confidence: confidence, evidence: strings.Join(details, "；")}
	}
	if successfulRounds >= 2 && cnameChecked && !now.After(cdnNegativeFreshUntil) {
		return cdnFinding{known: true, confidence: "medium", evidence: "至少兩輪成功重測未發現已知CDN訊號（快照" + cdnSnapshot + "）"}
	}
	if successfulRounds >= 2 && now.After(cdnNegativeFreshUntil) {
		return cdnFinding{evidence: "內建CDN快照已過期（快照" + cdnSnapshot + "）"}
	}
	if successfulRounds >= 2 && !cnameChecked {
		return cdnFinding{evidence: "CNAME查詢未完成，無法排除CDN"}
	}
	return cdnFinding{}
}

func cdnFromHeaders(headers http.Header) []cdnEvidence {
	rules := [...]struct {
		header   string
		provider string
	}{
		{"Cf-Ray", "Cloudflare"},
		{"X-Amz-Cf-Id", "CloudFront"},
		{"X-Amz-Cf-Pop", "CloudFront"},
		{"X-Fastly-Request-Id", "Fastly"},
		{"X-Akamai-Transformed", "Akamai"},
		{"Akamai-Grn", "Akamai"},
		{"X-Azure-Ref", "Azure Front Door"},
	}
	result := make([]cdnEvidence, 0, 2)
	for _, rule := range rules {
		if headers.Get(rule.header) != "" {
			result = append(result, cdnEvidence{layer: cdnLayerHTTP, provider: rule.provider, detail: "HTTP強訊號:" + rule.header})
		}
	}
	return result
}

func cdnFromCNAME(cname string) []cdnEvidence {
	host := normalizeDomain(cname)
	rules := [...]struct {
		suffix   string
		provider string
	}{
		{"cloudfront.net", "CloudFront"},
		{"fastly.net", "Fastly"},
		{"fastlylb.net", "Fastly"},
		{"akamaiedge.net", "Akamai"},
		{"akamaized.net", "Akamai"},
		{"edgekey.net", "Akamai"},
		{"edgesuite.net", "Akamai"},
		{"akamai.net", "Akamai"},
		{"azurefd.net", "Azure Front Door"},
		{"azureedge.net", "Azure Front Door"},
		{"cdn.cloudflare.net", "Cloudflare"},
	}
	for _, rule := range rules {
		if host == rule.suffix || strings.HasSuffix(host, "."+rule.suffix) {
			return []cdnEvidence{{layer: cdnLayerDNS, provider: rule.provider, detail: "CNAME特徵:" + rule.suffix}}
		}
	}
	return nil
}

func cdnFromIP(ip netip.Addr) []cdnEvidence {
	result := make([]cdnEvidence, 0, 1)
	for _, rule := range cdnPrefixRules {
		if rule.prefix.Contains(ip) {
			result = append(result, cdnEvidence{layer: cdnLayerIP, provider: rule.provider, detail: "IP網段快照(" + cdnSnapshot + "): " + rule.provider})
		}
	}
	return result
}

type cdnPrefixRule struct {
	provider string
	prefix   netip.Prefix
}

func mustCDNPrefixes(raw string) []cdnPrefixRule {
	fields := strings.Fields(raw)
	if len(fields)%2 != 0 {
		panic("invalid embedded CDN prefix data")
	}
	result := make([]cdnPrefixRule, 0, len(fields)/2)
	for index := 0; index < len(fields); index += 2 {
		provider := fields[index]
		if provider == "AzureFrontDoor" {
			provider = "Azure Front Door"
		}
		result = append(result, cdnPrefixRule{provider: provider, prefix: netip.MustParsePrefix(fields[index+1])})
	}
	return result
}

// Minimal IPv4-only snapshot used by this IPv4 scanner:
// Cloudflare ips-v4; AWS ip-ranges service=CLOUDFRONT; Fastly public-ip-list;
// Azure service tag AzureFrontDoor.Frontend. Source versions are documented in
// THIRD_PARTY_NOTICES.md.
var cdnPrefixRules = mustCDNPrefixes(`
Cloudflare 173.245.48.0/20
Cloudflare 103.21.244.0/22
Cloudflare 103.22.200.0/22
Cloudflare 103.31.4.0/22
Cloudflare 141.101.64.0/18
Cloudflare 108.162.192.0/18
Cloudflare 190.93.240.0/20
Cloudflare 188.114.96.0/20
Cloudflare 197.234.240.0/22
Cloudflare 198.41.128.0/17
Cloudflare 162.158.0.0/15
Cloudflare 104.16.0.0/13
Cloudflare 104.24.0.0/14
Cloudflare 172.64.0.0/13
Cloudflare 131.0.72.0/22
CloudFront 23.228.249.0/24
CloudFront 120.52.22.96/27
CloudFront 23.228.222.0/24
CloudFront 205.251.249.0/24
CloudFront 180.163.57.128/26
CloudFront 23.228.220.0/24
CloudFront 204.246.168.0/22
CloudFront 111.13.171.128/26
CloudFront 18.160.0.0/15
CloudFront 205.251.252.0/23
CloudFront 54.192.0.0/16
CloudFront 204.246.173.0/24
CloudFront 23.228.244.0/24
CloudFront 54.230.200.0/21
CloudFront 120.253.240.192/26
CloudFront 23.234.192.0/18
CloudFront 116.129.226.128/26
CloudFront 130.176.0.0/17
CloudFront 3.173.192.0/18
CloudFront 108.156.0.0/14
CloudFront 99.86.0.0/16
CloudFront 23.228.214.0/24
CloudFront 23.228.213.0/24
CloudFront 13.32.0.0/15
CloudFront 120.253.245.128/26
CloudFront 13.224.0.0/14
CloudFront 70.132.0.0/18
CloudFront 15.158.0.0/16
CloudFront 111.13.171.192/26
CloudFront 13.249.0.0/16
CloudFront 18.238.0.0/15
CloudFront 18.244.0.0/15
CloudFront 205.251.208.0/20
CloudFront 3.165.0.0/16
CloudFront 3.168.0.0/14
CloudFront 23.228.251.0/24
CloudFront 65.9.128.0/18
CloudFront 130.176.128.0/18
CloudFront 23.228.221.0/24
CloudFront 23.228.248.0/24
CloudFront 58.254.138.0/25
CloudFront 205.251.206.0/23
CloudFront 54.230.208.0/20
CloudFront 3.160.0.0/14
CloudFront 116.129.226.0/25
CloudFront 23.91.0.0/19
CloudFront 52.222.128.0/17
CloudFront 18.164.0.0/15
CloudFront 111.13.185.32/27
CloudFront 64.252.128.0/18
CloudFront 205.251.254.0/24
CloudFront 3.166.0.0/15
CloudFront 54.230.224.0/19
CloudFront 71.152.0.0/17
CloudFront 216.137.32.0/19
CloudFront 204.246.172.0/24
CloudFront 205.251.202.0/23
CloudFront 18.172.0.0/15
CloudFront 120.52.39.128/27
CloudFront 118.193.97.64/26
CloudFront 3.164.64.0/18
CloudFront 18.154.0.0/15
CloudFront 3.173.0.0/17
CloudFront 54.240.128.0/18
CloudFront 205.251.250.0/23
CloudFront 180.163.57.0/25
CloudFront 52.46.0.0/18
CloudFront 3.174.0.0/15
CloudFront 52.82.128.0/19
CloudFront 54.230.0.0/17
CloudFront 54.230.128.0/18
CloudFront 54.239.128.0/18
CloudFront 130.176.224.0/20
CloudFront 36.103.232.128/26
CloudFront 52.84.0.0/15
CloudFront 143.204.0.0/16
CloudFront 144.220.0.0/16
CloudFront 120.52.153.192/26
CloudFront 23.228.250.0/24
CloudFront 119.147.182.0/25
CloudFront 120.232.236.0/25
CloudFront 111.13.185.64/27
CloudFront 3.164.0.0/18
CloudFront 3.172.64.0/18
CloudFront 54.182.0.0/16
CloudFront 58.254.138.128/26
CloudFront 120.253.245.192/27
CloudFront 54.239.192.0/19
CloudFront 18.68.0.0/16
CloudFront 18.64.0.0/14
CloudFront 120.52.12.64/26
CloudFront 24.110.32.0/19
CloudFront 99.84.0.0/16
CloudFront 205.251.204.0/23
CloudFront 130.176.192.0/19
CloudFront 23.228.223.0/24
CloudFront 23.228.212.0/24
CloudFront 52.124.128.0/17
CloudFront 204.246.164.0/22
CloudFront 13.35.0.0/16
CloudFront 204.246.174.0/23
CloudFront 3.164.128.0/17
CloudFront 24.110.128.0/17
CloudFront 3.172.0.0/18
CloudFront 36.103.232.0/25
CloudFront 119.147.182.128/26
CloudFront 118.193.97.128/25
CloudFront 120.232.236.128/26
CloudFront 204.246.176.0/20
CloudFront 65.8.0.0/16
CloudFront 65.9.0.0/17
CloudFront 108.138.0.0/15
CloudFront 120.253.241.160/27
CloudFront 3.173.128.0/18
CloudFront 51.74.192.0/18
CloudFront 64.252.64.0/18
CloudFront 13.113.196.64/26
CloudFront 13.113.203.0/24
CloudFront 52.199.127.192/26
CloudFront 57.182.253.0/24
CloudFront 57.183.42.0/25
CloudFront 13.124.199.0/24
CloudFront 3.35.130.128/25
CloudFront 52.78.247.128/26
CloudFront 13.203.133.0/26
CloudFront 13.233.177.192/26
CloudFront 15.207.13.128/25
CloudFront 15.207.213.128/25
CloudFront 52.66.194.128/26
CloudFront 13.228.69.0/24
CloudFront 47.129.82.0/24
CloudFront 47.129.83.0/24
CloudFront 47.129.84.0/24
CloudFront 52.220.191.0/26
CloudFront 13.210.67.128/26
CloudFront 13.54.63.128/26
CloudFront 3.107.43.128/25
CloudFront 3.107.44.0/25
CloudFront 3.107.44.128/25
CloudFront 43.218.56.128/26
CloudFront 43.218.56.192/26
CloudFront 43.218.56.64/26
CloudFront 43.218.71.0/26
CloudFront 99.79.169.0/24
CloudFront 18.192.142.0/23
CloudFront 18.199.68.0/22
CloudFront 18.199.72.0/22
CloudFront 18.199.76.0/22
CloudFront 35.158.136.0/24
CloudFront 52.57.254.0/24
CloudFront 18.200.212.0/23
CloudFront 52.212.248.0/26
CloudFront 13.134.24.0/23
CloudFront 13.134.94.0/23
CloudFront 18.175.65.0/24
CloudFront 18.175.66.0/24
CloudFront 18.175.67.0/24
CloudFront 3.10.17.128/25
CloudFront 3.11.53.0/24
CloudFront 52.56.127.0/25
CloudFront 15.188.184.0/24
CloudFront 51.44.234.0/23
CloudFront 51.44.236.0/23
CloudFront 51.44.238.0/23
CloudFront 52.47.139.0/24
CloudFront 3.29.40.128/26
CloudFront 3.29.40.192/26
CloudFront 3.29.40.64/26
CloudFront 3.29.57.0/26
CloudFront 18.229.220.192/26
CloudFront 18.230.229.0/24
CloudFront 18.230.230.0/25
CloudFront 54.233.255.128/26
CloudFront 56.125.46.0/24
CloudFront 56.125.47.0/32
CloudFront 56.125.48.0/24
CloudFront 3.231.2.0/25
CloudFront 3.234.232.224/27
CloudFront 3.236.169.192/26
CloudFront 3.236.48.0/23
CloudFront 34.195.252.0/24
CloudFront 34.226.14.0/24
CloudFront 44.220.194.0/23
CloudFront 44.220.196.0/23
CloudFront 44.220.198.0/23
CloudFront 44.220.200.0/23
CloudFront 44.220.202.0/23
CloudFront 44.222.66.0/24
CloudFront 13.59.250.0/26
CloudFront 18.216.170.128/25
CloudFront 3.128.93.0/24
CloudFront 3.134.215.0/24
CloudFront 3.146.232.0/22
CloudFront 3.147.164.0/22
CloudFront 3.147.244.0/22
CloudFront 52.15.127.128/26
CloudFront 3.101.158.0/23
CloudFront 52.52.191.128/26
CloudFront 34.216.51.0/25
CloudFront 34.223.12.224/27
CloudFront 34.223.80.192/26
CloudFront 35.162.63.192/26
CloudFront 35.167.191.128/26
CloudFront 35.93.168.0/23
CloudFront 35.93.170.0/23
CloudFront 35.93.172.0/23
CloudFront 44.227.178.0/24
CloudFront 44.234.108.128/25
CloudFront 44.234.90.252/30
Fastly 23.235.32.0/20
Fastly 43.249.72.0/22
Fastly 103.244.50.0/24
Fastly 103.245.222.0/23
Fastly 103.245.224.0/24
Fastly 104.156.80.0/20
Fastly 140.248.64.0/18
Fastly 140.248.128.0/17
Fastly 146.75.0.0/17
Fastly 151.101.0.0/16
Fastly 157.52.64.0/18
Fastly 167.82.0.0/17
Fastly 167.82.128.0/20
Fastly 167.82.160.0/20
Fastly 167.82.224.0/20
Fastly 172.111.64.0/18
Fastly 185.31.16.0/22
Fastly 199.27.72.0/21
Fastly 199.232.0.0/16
AzureFrontDoor 4.145.22.160/29
AzureFrontDoor 4.147.44.8/29
AzureFrontDoor 4.173.102.138/31
AzureFrontDoor 4.173.103.144/29
AzureFrontDoor 4.188.10.28/30
AzureFrontDoor 4.188.12.24/29
AzureFrontDoor 4.191.92.24/29
AzureFrontDoor 4.199.29.134/31
AzureFrontDoor 4.199.29.184/29
AzureFrontDoor 4.208.127.240/29
AzureFrontDoor 4.216.8.160/29
AzureFrontDoor 4.223.184.160/30
AzureFrontDoor 4.232.98.112/29
AzureFrontDoor 13.73.248.8/29
AzureFrontDoor 13.80.194.200/29
AzureFrontDoor 13.105.221.0/24
AzureFrontDoor 13.107.208.0/24
AzureFrontDoor 13.107.213.0/24
AzureFrontDoor 13.107.224.0/24
AzureFrontDoor 13.107.226.0/24
AzureFrontDoor 13.107.231.0/24
AzureFrontDoor 13.107.234.0/23
AzureFrontDoor 13.107.237.0/24
AzureFrontDoor 13.107.238.0/23
AzureFrontDoor 13.107.246.0/24
AzureFrontDoor 13.107.253.0/24
AzureFrontDoor 20.15.221.160/29
AzureFrontDoor 20.17.125.72/29
AzureFrontDoor 20.21.37.32/29
AzureFrontDoor 20.36.120.96/29
AzureFrontDoor 20.37.64.96/29
AzureFrontDoor 20.37.156.112/29
AzureFrontDoor 20.37.192.88/29
AzureFrontDoor 20.37.224.96/29
AzureFrontDoor 20.38.84.64/29
AzureFrontDoor 20.38.136.96/29
AzureFrontDoor 20.39.11.0/29
AzureFrontDoor 20.41.4.80/29
AzureFrontDoor 20.41.64.112/29
AzureFrontDoor 20.41.192.96/29
AzureFrontDoor 20.42.4.112/29
AzureFrontDoor 20.42.129.144/29
AzureFrontDoor 20.42.224.96/29
AzureFrontDoor 20.43.41.128/29
AzureFrontDoor 20.43.64.88/29
AzureFrontDoor 20.43.128.104/29
AzureFrontDoor 20.45.112.96/29
AzureFrontDoor 20.45.192.96/29
AzureFrontDoor 20.51.7.32/29
AzureFrontDoor 20.52.95.240/29
AzureFrontDoor 20.59.82.180/30
AzureFrontDoor 20.72.18.240/29
AzureFrontDoor 20.97.39.120/29
AzureFrontDoor 20.113.254.80/29
AzureFrontDoor 20.119.28.40/29
AzureFrontDoor 20.150.160.72/29
AzureFrontDoor 20.189.106.72/29
AzureFrontDoor 20.192.161.96/29
AzureFrontDoor 20.192.225.40/29
AzureFrontDoor 20.197.145.0/29
AzureFrontDoor 20.197.145.8/31
AzureFrontDoor 20.210.70.68/30
AzureFrontDoor 20.215.4.200/29
AzureFrontDoor 20.217.44.200/29
AzureFrontDoor 40.67.48.96/29
AzureFrontDoor 40.74.30.64/29
AzureFrontDoor 40.80.56.96/29
AzureFrontDoor 40.80.168.96/29
AzureFrontDoor 40.80.184.112/29
AzureFrontDoor 40.82.248.72/29
AzureFrontDoor 40.89.16.96/29
AzureFrontDoor 40.90.64.0/22
AzureFrontDoor 40.90.68.0/24
AzureFrontDoor 40.90.70.0/23
AzureFrontDoor 48.192.88.240/30
AzureFrontDoor 48.195.102.234/31
AzureFrontDoor 48.195.103.72/29
AzureFrontDoor 48.199.205.88/30
AzureFrontDoor 48.204.185.120/29
AzureFrontDoor 48.223.80.232/29
AzureFrontDoor 51.12.41.0/29
AzureFrontDoor 51.12.193.0/29
AzureFrontDoor 51.53.28.216/29
AzureFrontDoor 51.57.122.168/29
AzureFrontDoor 51.104.24.88/29
AzureFrontDoor 51.105.80.96/29
AzureFrontDoor 51.105.88.96/29
AzureFrontDoor 51.107.48.96/29
AzureFrontDoor 51.107.144.96/29
AzureFrontDoor 51.120.40.96/29
AzureFrontDoor 51.120.224.96/29
AzureFrontDoor 51.137.160.88/29
AzureFrontDoor 52.136.48.96/29
AzureFrontDoor 52.140.104.96/29
AzureFrontDoor 52.150.136.112/29
AzureFrontDoor 52.228.80.112/29
AzureFrontDoor 57.166.0.112/29
AzureFrontDoor 57.175.44.132/31
AzureFrontDoor 57.175.48.144/29
AzureFrontDoor 68.210.172.152/29
AzureFrontDoor 68.221.92.24/29
AzureFrontDoor 74.144.32.230/31
AzureFrontDoor 74.144.33.0/29
AzureFrontDoor 102.133.56.80/29
AzureFrontDoor 102.133.216.80/29
AzureFrontDoor 104.212.67.0/24
AzureFrontDoor 104.212.68.0/24
AzureFrontDoor 150.171.1.16/28
AzureFrontDoor 150.171.22.0/23
AzureFrontDoor 150.171.26.0/24
AzureFrontDoor 150.171.84.0/22
AzureFrontDoor 150.171.88.0/23
AzureFrontDoor 150.171.109.0/24
AzureFrontDoor 150.171.110.0/23
AzureFrontDoor 150.171.112.0/24
AzureFrontDoor 158.23.108.48/29
AzureFrontDoor 172.186.128.134/31
AzureFrontDoor 172.186.128.152/29
AzureFrontDoor 172.192.205.92/31
AzureFrontDoor 172.192.208.96/29
AzureFrontDoor 172.204.165.104/29
AzureFrontDoor 191.233.9.112/29
AzureFrontDoor 191.235.224.88/29
`)
