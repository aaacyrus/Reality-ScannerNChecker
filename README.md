# Reality Scanner & Checker

中英雙語互動式終端工具，用於掃描鄰近 IPv4 TLS 端點、檢測 REALITY 目標條件，並排列最佳 `IP + SNI` 組合。

A bilingual interactive terminal tool that discovers nearby IPv4 TLS endpoints, validates REALITY target requirements, and ranks the best `IP + SNI` pairs.

> [!CAUTION]
> 只可掃描你擁有或已獲明確授權測試的網絡。Only scan networks you own or are explicitly authorized to test.

## 功能特色 / Highlights

- **雙語互動介面 / Bilingual UI**：繁體中文及英文數字選單，按 Enter 採用預設值
- **終端顯示 / Terminal output**：彩色狀態、spinner、進度條及結果表；管道或重定向時自動改用純文字
- **公網 IP 偵測 / Public IP detection**：自動偵測，亦可選擇候選地址或手動輸入
- **掃描範圍 / Scan ranges**：多種有限 CIDR 範圍及進階無限掃描模式
- **TCP 443**：開始前顯示實際 CIDR、IP 數量及預估耗時
- **完整檢測 / Full validation**：TLS 1.3、X25519、HTTP/2、SNI、憑證、地區、封鎖、CDN、熱門網站及重新導向
- **三輪驗證 / Three-round verification**：至少成功 2 輪才會進入排名
- **105 分評分 / 105-point scoring**：TLS/HTTP 按合格列表中的最快延遲比例計分，並綜合穩定性、CDN、熱門度、域名層級及憑證有效期
- **不建立報告 / No report files**：結果只顯示在終端，不會建立歷史紀錄、JSON 或 CSV

## 快速使用 / Quick start

需要 Go `1.26` 或以上版本。以下指令適用於 Linux、macOS 與 Windows；會下載並直接執行目前公開 `main` 分支的程式碼。

Requires Go `1.26` or later. The following command works on Linux, macOS, and Windows; it downloads and runs the current public `main` branch:

```sh
go run github.com/aaacyrus/Reality-ScannerNChecker@latest
```

### 本機開發 / Local development

如要查看或修改原始碼：

To inspect or modify the source code:

```sh
git clone https://github.com/aaacyrus/Reality-ScannerNChecker.git
cd Reality-ScannerNChecker
go run .
```

預編譯執行檔會在發布後提供於 [Releases](https://github.com/aaacyrus/Reality-ScannerNChecker/releases)。

Prebuilt executables will be available from [Releases](https://github.com/aaacyrus/Reality-ScannerNChecker/releases) after a version is published.

## 使用方法 / Usage

啟動後依畫面操作：

Follow the on-screen prompts after launch:

1. 選擇繁體中文或英文 / Choose Traditional Chinese or English.
2. 選擇是否更新檢測資料 / Choose whether to update detector data.
3. 確認自動偵測的公網 IPv4 / Confirm the detected public IPv4 address.
4. 選擇掃描範圍及速度模式 / Choose a scan range and speed profile.
5. 核對 CIDR、IP 數量及端口後開始 / Review the CIDR, address count, and port before starting.
6. 查看最佳 IP、SNI、排名及淘汰原因 / Review the best IP, SNI, ranking, and rejection reasons.

- 掃描或檢測期間輸入 `0` 並按 Enter 可停止；也可按 `Ctrl+C` 結束。
- Enter `0` during scanning or validation to stop, or press `Ctrl+C` to exit.
- 設定 `NO_COLOR=1` 可停用顏色 / Set `NO_COLOR=1` to disable colors.
- 中途停止會放棄該次結果 / Stopping early discards the current run.

## 網絡行為 / Network behavior

- 掃描、公網 IP 偵測及候選驗證均使用直連並忽略代理環境變數。
- Scanning, public-IP detection, and candidate validation use direct connections and ignore proxy environment variables.
- 國別資料更新可使用系統 HTTP 代理；未取得資料時，工具會以「無法判斷地區」淘汰候選。
- Country-data updates may use the system HTTP proxy; without the database, candidates are rejected as location unknown.
- 掃描固定使用 TCP `443` / Scanning is fixed to TCP `443`.

## Dependencies

- 掃描與檢測邏輯為本專案自行實作；國別判斷可選用外部 GeoIP 資料庫。
- Scanning and validation logic is implemented in this project; country lookup optionally uses an external GeoIP database.

## 授權 / License

本專案採用 [Mozilla Public License 2.0](LICENSE)（`MPL-2.0`）。

This project is licensed under the [Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).

## Disclaimer

本工具僅供合法的技術研究、網絡管理及已獲授權的測試用途。

This tool is intended only for lawful technical research, network administration, and authorized testing.
