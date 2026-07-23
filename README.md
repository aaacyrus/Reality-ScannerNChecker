# Reality Scanner & Checker

## English

An interactive terminal tool that discovers nearby IPv4 TLS endpoints, validates REALITY target requirements, and ranks the best `IP + SNI` combinations.

> [!CAUTION]
> Only scan networks you own or are explicitly authorized to test.

### Highlights

- Bilingual interactive UI: Traditional Chinese and English numeric menus, with Enter accepting defaults
- Terminal output: colored status, spinner, progress bar, and result tables; automatically falls back to plain text when piped or redirected
- Public IP detection: automatically detects a public IPv4 address, or lets you choose a candidate or enter one manually
- Scan ranges: several finite CIDR ranges plus an advanced infinite-scan mode
- TCP 443: shows the effective CIDR, IP count, and estimated duration before scanning
- Full validation: TLS 1.3, X25519, HTTP/2, SNI, certificates, location, blocking, CDN, popular websites, and redirects
- Three verification rounds: candidates need at least two successful rounds before ranking
- 105-point score: TLS/HTTP latency is scored against the fastest qualified candidate, together with stability, CDN, popularity, domain level, and certificate validity
- No report files: results stay in the terminal; no history, JSON, or CSV files are created

### Quick start

#### Linux x86-64 (amd64)

This command finds the Linux amd64 asset from the latest GitHub Release, downloads it to `/tmp`, and runs it. Go is not required.

```sh
curl -fsSL https://api.github.com/repos/aaacyrus/Reality-ScannerNChecker/releases/latest |
  grep -o 'https://[^" ]*reality-scanner-checker_[^" ]*_linux_amd64' | head -n 1 |
  xargs -I{} sh -c 'curl -fL "{}" -o /tmp/reality-scanner-checker && chmod +x /tmp/reality-scanner-checker && /tmp/reality-scanner-checker'
```

For other Linux, macOS, and Windows architectures, download the matching asset from [Releases](https://github.com/aaacyrus/Reality-ScannerNChecker/releases). On Linux/macOS, run `chmod +x <filename>` after downloading.

#### Local development

To inspect, modify, or run from source, install Go `1.26` or later:

```sh
git clone https://github.com/aaacyrus/Reality-ScannerNChecker.git
cd Reality-ScannerNChecker
go run .
```

### Usage

After launching, follow the on-screen prompts:

1. Choose Traditional Chinese or English.
2. Choose whether to update detector data.
3. Confirm the detected public IPv4 address.
4. Choose a scan range and speed profile.
5. Review the CIDR, address count, and port, then start.
6. Review the best IP, SNI, ranking, and rejection reasons.

- Enter `0` during scanning or validation to stop, or press `Ctrl+C` to exit.
- Set `NO_COLOR=1` to disable colors.
- Stopping early discards the current run.

### Network behavior

- Scanning, public-IP detection, and candidate validation use direct connections and ignore proxy environment variables.
- Country-data updates may use the system HTTP proxy; without the database, candidates are rejected as location unknown.
- Scanning is fixed to TCP `443`.

### Dependencies

- Scanning and validation logic is implemented in this project; country lookup optionally uses an external GeoIP database.

### License

This project is licensed under the [Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).

### Disclaimer

This tool is intended only for lawful technical research, network administration, and authorized testing.

## 繁體中文

互動式終端工具，用於掃描鄰近 IPv4 TLS 端點、檢測 REALITY 目標條件，並排列最佳 `IP + SNI` 組合。

> [!CAUTION]
> 只可掃描你擁有或已獲明確授權測試的網絡。

### 功能特色

- 雙語互動介面：繁體中文及英文數字選單，按 Enter 採用預設值
- 終端顯示：彩色狀態、spinner、進度條及結果表；管道或重定向時自動改用純文字
- 公網 IP 偵測：自動偵測，亦可選擇候選地址或手動輸入
- 掃描範圍：多種有限 CIDR 範圍及進階無限掃描模式
- TCP 443：開始前顯示實際 CIDR、IP 數量及預估耗時
- 完整檢測：TLS 1.3、X25519、HTTP/2、SNI、憑證、地區、封鎖、CDN、熱門網站及重新導向
- 三輪驗證：至少成功 2 輪才會進入排名
- 105 分評分：TLS/HTTP 按合格列表中的最快延遲比例計分，並綜合穩定性、CDN、熱門度、域名層級及憑證有效期
- 不建立報告：結果只顯示在終端，不會建立歷史紀錄、JSON 或 CSV

### 快速使用

#### Linux x86-64（amd64）

以下指令會從最新 GitHub Release 自動找出 Linux amd64 執行檔、下載到 `/tmp` 並啟動；不需要安裝 Go。

```sh
curl -fsSL https://api.github.com/repos/aaacyrus/Reality-ScannerNChecker/releases/latest |
  grep -o 'https://[^" ]*reality-scanner-checker_[^" ]*_linux_amd64' | head -n 1 |
  xargs -I{} sh -c 'curl -fL "{}" -o /tmp/reality-scanner-checker && chmod +x /tmp/reality-scanner-checker && /tmp/reality-scanner-checker'
```

其他 Linux、macOS 及 Windows 架構請前往 [Releases](https://github.com/aaacyrus/Reality-ScannerNChecker/releases) 下載相符檔案。Linux／macOS 下載後請執行 `chmod +x <檔名>`。

#### 本機開發

如要查看、修改或直接從原始碼執行，請先安裝 Go `1.26` 或以上版本：

```sh
git clone https://github.com/aaacyrus/Reality-ScannerNChecker.git
cd Reality-ScannerNChecker
go run .
```

### 使用方法

啟動後依畫面操作：

1. 選擇繁體中文或英文。
2. 選擇是否更新檢測資料。
3. 確認自動偵測的公網 IPv4。
4. 選擇掃描範圍及速度模式。
5. 核對 CIDR、IP 數量及端口後開始。
6. 查看最佳 IP、SNI、排名及淘汰原因。

- 掃描或檢測期間輸入 `0` 並按 Enter 可停止；也可按 `Ctrl+C` 結束。
- 設定 `NO_COLOR=1` 可停用顏色。
- 中途停止會放棄該次結果。

### 網絡行為

- 掃描、公網 IP 偵測及候選驗證均使用直連並忽略代理環境變數。
- 國別資料更新可使用系統 HTTP 代理；未取得資料時，工具會以「無法判斷地區」淘汰候選。
- 掃描固定使用 TCP `443`。

### 依賴

- 掃描與檢測邏輯為本專案自行實作；國別判斷可選用外部 GeoIP 資料庫。

### 授權

本專案採用 [Mozilla Public License 2.0](LICENSE)（`MPL-2.0`）。

### 免責聲明

本工具僅供合法的技術研究、網絡管理及已獲授權的測試用途。
