# 第三方資料聲明 / Third-Party Data Notices

## 繁體中文

### Chrome 使用者體驗報告（CrUX）

內建熱門網站索引衍生自 Google 的 Chrome 使用者體驗報告全球資料集，資料月份為 `202606`。Google 以 [Creative Commons 姓名標示 4.0 國際授權](https://creativecommons.org/licenses/by/4.0/)（CC BY 4.0）提供 CrUX 資料；本專案的 MPL-2.0 授權不取代該資料授權。

- 原始資料集與方法：[Chrome UX Report](https://developer.chrome.com/docs/crux/methodology)
- 取得快照：[zakird/crux-top-lists](https://github.com/zakird/crux-top-lists/blob/main/data/global/202606.csv.gz)，其內容是公開 CrUX BigQuery 資料的快取
- 修改：保留 `rank <= 100000`、抽取並小寫化精確 hostname、移除尾端句點、以 `LC_ALL=C` 排序及去重，再編碼為 Bloom filter
- 去重後 hostname：`99,946`
- Bloom filter：`2,879,003` bits、`20` hashes；預期假陽性率約 `9.76e-7`，沒有假陰性
- 原始 gzip SHA-256：`c3eeeeda07fcde37093017a74f067d5bf2b5cf8de8a4fc6b0236eb517d65a306`
- 正規化 hostname SHA-256：`79417f019ad998b7ea9b9da8489f41596ced08a4263e9f3dddbc7f8709b157f6`
- 內建二進位 Bloom filter：`359,876` bytes；SHA-256 `6726d1155295c774cb0900f08825c8c94c9c9baf10a07750253cc4b5db8e93db`

Bloom filter 的假陽性只會把少量未入榜 hostname 保守地標為熱門，不會錯給「非熱門」分數。本專案及其修改不代表 Google 認可或背書。

重建方式（輸入檔固定為上列 `202606.csv.gz` 及 SHA-256）：

```sh
gzip -dc 202606.csv.gz |
  awk -F, 'NR > 1 && ($2 + 0) <= 100000 { host=$1; sub(/^https?:\/\//, "", host); sub(/\/.*/, "", host); sub(/:[0-9]+$/, "", host); print tolower(host) }' |
  LC_ALL=C sort -u > crux_top_100k_hosts.txt
go run internal/checker/data/generate_bloom.go crux_top_100k_hosts.txt > crux_top_100k_202606.bin
```

`202606` 未命中結果只在 `2026-09-12 23:59:59 UTC` 前視為有效；期限後，命中仍保守標示為熱門，未命中則退回未知。

### CDN IP 範圍

內建檔案只保留本 IPv4 掃描器需要的供應商、網段及版本資料，不包含完整來源回應：

- Cloudflare：官方 [`ips-v4`](https://www.cloudflare.com/ips-v4)，`15` 個 IPv4 網段，擷取日期 `2026-07-23`；來源 SHA-256 `f02c6d83bc01ab0ae8577160e036d700c7455359bce054df884e5d7d9e4e9e7b`
- Amazon CloudFront：AWS [`ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json) 中 `service == CLOUDFRONT`，`209` 個 IPv4 網段；`syncToken=1784785625`、`createDate=2026-07-23-05-47-05`；來源 SHA-256 `46fa59b4bf77877e7e01b1fd6c50c84a8313f19b40cc6fd777d65cc313072078`
- Fastly：官方 [`public-ip-list`](https://api.fastly.com/public-ip-list)，`19` 個 IPv4 網段，擷取日期 `2026-07-23`；來源 SHA-256 `d0fa4abe04cded896cf1a1d1a1c16ce2861ea4feb837ebd045a89c7b06a15ab5`
- Azure Front Door：Microsoft [Azure IP Ranges and Service Tags](https://www.microsoft.com/en-us/download/details.aspx?id=56519) 的 `ServiceTags_Public_20260720.json` 中 `AzureFrontDoor.Frontend`，`123` 個 IPv4 網段；全檔 `changeNumber=410`、服務標籤 `changeNumber=42`；來源 SHA-256 `8510a53ca89c26a8121ad55f2a1130d4753949479feb744566f0ba46be2380ce`

過濾及串接後的 `provider CIDR` 文字 SHA-256 為 `622a186bf7485e464d4bb399579d8f850c8c21d535fbff16d2275a8fae1fa4d5`。未命中只在 `2026-08-03 23:59:59 UTC` 前可作為「未發現受支援 CDN 訊號」的負面證據；期限後未命中退回未知，過期 IP 命中只作低可信度的保守提示。

## English

### Chrome UX Report (CrUX)

The embedded popular-site index is derived from Google's global Chrome UX Report dataset for data month `202606`. Google licenses CrUX datasets under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0); this project's MPL-2.0 license does not replace that data license.

- Dataset and methodology: [Chrome UX Report](https://developer.chrome.com/docs/crux/methodology)
- Snapshot retrieval: [zakird/crux-top-lists](https://github.com/zakird/crux-top-lists/blob/main/data/global/202606.csv.gz), a cache of the public CrUX BigQuery data
- Modifications: retained `rank <= 100000`, extracted and lowercased exact hostnames, removed trailing dots, sorted with `LC_ALL=C`, deduplicated them, and encoded the result as a Bloom filter
- Deduplicated hostnames: `99,946`
- Bloom filter: `2,879,003` bits and `20` hashes; expected false-positive rate approximately `9.76e-7`, with no false negatives
- Source gzip SHA-256: `c3eeeeda07fcde37093017a74f067d5bf2b5cf8de8a4fc6b0236eb517d65a306`
- Normalized hostname SHA-256: `79417f019ad998b7ea9b9da8489f41596ced08a4263e9f3dddbc7f8709b157f6`
- Embedded binary Bloom filter: `359,876` bytes; SHA-256 `6726d1155295c774cb0900f08825c8c94c9c9baf10a07750253cc4b5db8e93db`

A Bloom-filter false positive only conservatively labels a small number of unlisted hostnames as popular; it never grants the not-popular score incorrectly. This project and its modifications are not endorsed by Google.

Reproduction steps (with the input fixed to the `202606.csv.gz` file and SHA-256 above):

```sh
gzip -dc 202606.csv.gz |
  awk -F, 'NR > 1 && ($2 + 0) <= 100000 { host=$1; sub(/^https?:\/\//, "", host); sub(/\/.*/, "", host); sub(/:[0-9]+$/, "", host); print tolower(host) }' |
  LC_ALL=C sort -u > crux_top_100k_hosts.txt
go run internal/checker/data/generate_bloom.go crux_top_100k_hosts.txt > crux_top_100k_202606.bin
```

A `202606` miss is authoritative only through `2026-09-12 23:59:59 UTC`. After that deadline, matches remain conservative popular signals while misses become unknown.

### CDN IP ranges

The embedded data retains only the providers, prefixes, and versions needed by this IPv4 scanner, not the complete source responses:

- Cloudflare: official [`ips-v4`](https://www.cloudflare.com/ips-v4), `15` IPv4 prefixes, retrieved `2026-07-23`; source SHA-256 `f02c6d83bc01ab0ae8577160e036d700c7455359bce054df884e5d7d9e4e9e7b`
- Amazon CloudFront: entries where `service == CLOUDFRONT` in AWS [`ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json), `209` IPv4 prefixes; `syncToken=1784785625`, `createDate=2026-07-23-05-47-05`; source SHA-256 `46fa59b4bf77877e7e01b1fd6c50c84a8313f19b40cc6fd777d65cc313072078`
- Fastly: official [`public-ip-list`](https://api.fastly.com/public-ip-list), `19` IPv4 prefixes, retrieved `2026-07-23`; source SHA-256 `d0fa4abe04cded896cf1a1d1a1c16ce2861ea4feb837ebd045a89c7b06a15ab5`
- Azure Front Door: `AzureFrontDoor.Frontend` from Microsoft's [Azure IP Ranges and Service Tags](https://www.microsoft.com/en-us/download/details.aspx?id=56519) file `ServiceTags_Public_20260720.json`, `123` IPv4 prefixes; file `changeNumber=410`, service-tag `changeNumber=42`; source SHA-256 `8510a53ca89c26a8121ad55f2a1130d4753949479feb744566f0ba46be2380ce`

The filtered and concatenated `provider CIDR` text has SHA-256 `622a186bf7485e464d4bb399579d8f850c8c21d535fbff16d2275a8fae1fa4d5`. A miss can be used as negative evidence for “no supported CDN signal” only through `2026-08-03 23:59:59 UTC`; after that deadline, misses become unknown and stale IP matches are retained only as low-confidence conservative hints.
