# 建置操作說明 / Build Guide

## 支援平台 / Supported targets

| 作業系統 | 架構 | Go target | 格式 |
| --- | --- | --- | --- |
| Linux | x86 32-bit | `linux/386` | 原始可執行檔 |
| Linux | x86-64 | `linux/amd64` | 原始可執行檔 |
| Linux | ARM64 | `linux/arm64` | 原始可執行檔 |
| macOS | Intel | `darwin/amd64` | 原始可執行檔 |
| macOS | Apple Silicon | `darwin/arm64` | 原始可執行檔 |
| Windows | x86 32-bit | `windows/386` | `.exe` |
| Windows | x86-64 | `windows/amd64` | `.exe` |
| Windows | ARM64 | `windows/arm64` | `.exe` |

所有執行檔均直接輸出，不經 ZIP、tar 或其他壓縮。每次建置亦會產生
`BUILD_INFO.txt` 及 `SHA256SUMS`。

All executables are emitted directly without ZIP, tar, or other compression.
Every build also produces `BUILD_INFO.txt` and `SHA256SUMS`.

## 標準流程 / Standard workflow

### 1. 撰寫雙語說明 / Write bilingual notes

```sh
cp release-notes/TEMPLATE.md release-notes/v0.1.0.md
```

把標題版本改為 `v0.1.0`，並完成 `## 繁體中文` 與 `## English` 兩部分。
發佈腳本缺少任何一種語言時會拒絕執行。

Change the title version to `v0.1.0`, then complete both the
`## 繁體中文` and `## English` sections. Publishing is rejected if either
language section is missing.

### 2. 提交及推送 / Commit and push

先完成程式修改與測試，然後提交並推送目前分支：

```sh
git add <files>
git commit -m "<message>"
git push
```

建置及發佈腳本會重新 fetch upstream，並拒絕未提交、有未追蹤檔案、尚未
push、落後遠端或 detached HEAD 的狀態。

Finish and test the source changes, then commit and push the current branch.
The build and publish scripts fetch the upstream and refuse dirty, untracked,
unpushed, behind-remote, or detached-HEAD states.

### 3. 本機建置 / Local build

```sh
go test ./...
./scripts/build-all.sh v0.1.0
```

輸出會寫入 `dist/builds/v0.1.0/`，並由 `.gitignore` 排除。建置腳本不會
建立 Git tag、Actions Artifact 或 GitHub Release，也不會 push 或上傳任何
檔案。

Output is written to `dist/builds/v0.1.0/` and excluded by `.gitignore`. The
build script does not create a Git tag, Actions Artifact, or GitHub Release,
and it does not push or upload files.

### 4. 上傳建置檔案 / Upload build files

```sh
./scripts/publish-release.sh v0.1.0 release-notes/v0.1.0.md
```

發佈前必須人工輸入完整版本號確認。腳本只會上傳明確列出的八個未壓縮
執行檔、`BUILD_INFO.txt` 及 `SHA256SUMS`，
不會上傳 `dist/builds/` 目錄、專案目錄或其他檔案。新 Release 會綁定已
push 的目前 commit；更新既有 Release 時，tag 亦必須指向同一個 commit。

Publishing requires typing the full version as confirmation. The script uploads
only the eight explicitly listed uncompressed executables, `BUILD_INFO.txt`,
and `SHA256SUMS`. It never uploads the
`dist/builds/` directory, project directory, or any other file. A new release
targets the current pushed commit; an existing release tag must point to that
same commit.

Linux 及 macOS 使用者下載後需要加入執行權限：

```sh
chmod +x reality-scanner-checker_*
```

Linux and macOS users must add execute permission after downloading the raw
binary.

## 不使用 GitHub Actions / No GitHub Actions

本專案不設定 GitHub Actions 建置、Artifact 或 Release workflow。所有建置均在
本機完成，只有最後列明的建置檔案會經人工確認後上傳至 Private GitHub
Release。

This project does not configure a GitHub Actions build, artifact, or release
workflow. All builds run locally; only the explicitly listed build files are
uploaded to the private GitHub Release after manual confirmation.
