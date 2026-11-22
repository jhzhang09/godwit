#!/usr/bin/env bash
# 根据发版产物的 SHA256SUMS.txt 生成 Godwit 的 Homebrew Cask，并提交到 tap 仓库。
# 用法:
#   scripts/update-homebrew-tap.sh <version> <checksums_file>
# 环境变量:
#   HOMEBREW_TAP_DEPLOY_KEY  推送 tap 仓库用的 SSH Deploy Key 私钥（CI 优先使用）
#   TAP_GITHUB_TOKEN         推送 tap 仓库用的 PAT 令牌（备用）；均未设置时使用本机 SSH
#   TAP_REPO                 目标 tap 仓库，默认 jhzhang09/homebrew-tap
#   TAP_DRY_RUN              设为任意值时只把生成的文件写到 TAP_OUT（默认 ./tap-preview），不克隆、不推送
set -euo pipefail

version_raw="${1:?usage: update-homebrew-tap.sh <version> <checksums_file>}"
checksums="${2:?usage: update-homebrew-tap.sh <version> <checksums_file>}"
version="${version_raw#v}"
tap_repo="${TAP_REPO:-jhzhang09/homebrew-tap}"

if [[ ! -f "$checksums" ]]; then
  echo "Error: checksums file not found at $checksums" >&2
  exit 1
fi

# extract_sha 按完整文件名取哈希，确保与本次版本的产物对应。
extract_sha() {
  local file="$1" sha
  sha=$(awk -v f="$file" '$2 == f || $2 == "*" f {print $1; exit}' "$checksums")
  if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Error: no SHA-256 for $file in $checksums" >&2
    exit 1
  fi
  echo "$sha"
}

arm64_sha=$(extract_sha "godwit-${version}-arm64.dmg")
amd64_sha=$(extract_sha "godwit-${version}-amd64.dmg")

# generate 把 Cask 写到目录 $1。
generate() {
  local dir="$1"
  mkdir -p "$dir/Casks"

  # Cask 中的 #{...} 是 Ruby 插值，由 Homebrew 求值；${...} 由本脚本替换。
  cat <<EOF >"$dir/Casks/godwit.rb"
cask "godwit" do
  arch arm: "arm64", intel: "amd64"

  version "${version}"
  sha256 arm:   "${arm64_sha}",
         intel: "${amd64_sha}"

  url "https://github.com/jhzhang09/godwit/releases/download/v#{version}/godwit-#{version}-#{arch}.dmg"
  name "Godwit"
  desc "Unofficial fork of Godwit email client with native S/MIME support"
  homepage "https://github.com/jhzhang09/godwit"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: :monterey

  app "Godwit.app"
  binary "#{appdir}/Godwit.app/Contents/MacOS/Godwit", target: "godwit"

  postflight_steps do
    run "/usr/bin/xattr",
        args: ["-dr", "com.apple.quarantine", "{{appdir}}/Godwit.app"]
  end

  zap trash: [
    "~/Library/Application Support/Godwit",
    "~/Library/Preferences/email.godwit.app.plist",
    "~/Library/Saved Application State/email.godwit.app.savedState",
  ]
end
EOF

  # 有 Ruby 时先做语法检查，避免把坏文件推到 tap。
  if command -v ruby >/dev/null 2>&1; then
    ruby -c "$dir/Casks/godwit.rb" >/dev/null
  fi
}

if [[ -n "${TAP_DRY_RUN:-}" ]]; then
  out="${TAP_OUT:-tap-preview}"
  generate "$out"
  echo "Generated Homebrew Cask for v${version} in $out (dry run, nothing pushed)."
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ -n "${HOMEBREW_TAP_DEPLOY_KEY:-}" ]]; then
  key="$work/tap_key"
  known_hosts="$work/known_hosts"
  printf '%s\n' "$HOMEBREW_TAP_DEPLOY_KEY" > "$key"
  chmod 600 "$key"
  # api.github.com/meta 中的 github.com 官方 SSH 主机公钥
  echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" > "$known_hosts"
  export GIT_SSH_COMMAND="ssh -i $key -o IdentitiesOnly=yes -o UserKnownHostsFile=$known_hosts"
  remote="git@github.com:${tap_repo}.git"
elif [[ -n "${TAP_GITHUB_TOKEN:-}" ]]; then
  remote="https://x-access-token:${TAP_GITHUB_TOKEN}@github.com/${tap_repo}.git"
else
  remote="git@github.com:${tap_repo}.git"
fi
git clone --quiet --depth 1 "$remote" "$work/tap"
cd "$work/tap"
# CI 中以 github-actions[bot] 署名；本地运行沿用维护者自己的 Git 身份。
if [[ -n "${HOMEBREW_TAP_DEPLOY_KEY:-}" || -n "${TAP_GITHUB_TOKEN:-}" ]]; then
  git config user.name "github-actions[bot]"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
fi

generate .
if [[ -f README.md ]] && ! grep -q 'jhzhang09/tap/godwit' README.md; then
  cat <<'EOF' >> README.md

---

### 5. Godwit (`godwit`)

Open-source, AI-native desktop email client with native hardware-backed S/MIME support ([jhzhang09/godwit](https://github.com/jhzhang09/godwit)).

Install via Homebrew Cask:

```bash
brew install --cask jhzhang09/tap/godwit
```

Or tap first:

```bash
brew tap jhzhang09/tap
brew install --cask godwit
```

Upgrade to the latest release:

```bash
brew upgrade --cask godwit
```

> **Requirements & CLI:**
> - Requires **macOS 12 (Monterey) or later** (separate native builds for Apple Silicon `arm64` and Intel `amd64`).
> - Installs `/Applications/Godwit.app` and links the `godwit` command (`godwit mcp`, `godwit call`, `godwit --headless`) into Homebrew's `bin` directory.
> - Also supports in-app self-updates signed with this fork's update key.

> **macOS Gatekeeper Note:**
> Releases are ad-hoc signed and not notarized with an Apple Developer account.
> The cask automatically clears the quarantine attribute during installation. If macOS still blocks it on first launch, run:
> ```bash
> xattr -dr com.apple.quarantine /Applications/Godwit.app
> ```
> Or choose **System Settings → Privacy & Security → Open Anyway** after the first launch attempt.
EOF
  git add README.md
fi

git add Casks/godwit.rb
if git diff --cached --quiet; then
  echo "$tap_repo is already up to date with v${version}."
  exit 0
fi

git commit --quiet -m "godwit ${version}"
git push --quiet "$remote" HEAD:main
echo "Updated $tap_repo to v${version}."
