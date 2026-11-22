// The app as `mygo build` packages it. The release workflow signs with the
// Developer ID it imports and notarizes (release.yml); elsewhere builds are
// signed ad hoc.
const env = process.env;
const provisioningProfile = env.MACOS_PROVISIONING_PROFILE;
const entitlements = env.MACOS_ENTITLEMENTS;
if (Boolean(provisioningProfile) !== Boolean(entitlements)) {
  throw new Error("Set both MACOS_PROVISIONING_PROFILE and MACOS_ENTITLEMENTS for communication notifications");
}

export default {
  name: "Godwit",
  identifier: "email.godwit.app",
  // 本地功能预览版使用独立版本号，避免界面连接到已安装版本的旧后端。
  version: env.GODWIT_BUILD_VERSION || "1.39.3", // x-release-please-version
  copyright: "© 2026 The Godwit Authors",
  icon: "assets/icon.png",
  main: "./cmd/godwit",
  devUrl: "http://localhost:5173",
  devCommand: "cd web && bun run dev",
  buildCommand: "cd web && bun install --frozen-lockfile && bun run build",
  frontendDist: "web/dist",
  bindings: "web/src/mygo.ts",
  resources: ["LICENSE", "NOTICE"],
  i18n: { dir: "internal/i18n", source: "en" },
  macos: {
    icon: "assets/AppIcon.icon", // compiled with actool, which needs Xcode 26+; without it the app keeps icon's .icns
    // Set both only for a signed build with an authorized profile (.github/actions/macos-sign/README.md).
    provisioningProfile,
    infoPlist: { NSUserActivityTypes: ["INSendMessageIntent"] },
    signingIdentity: env.MACOS_SIGNING_IDENTITY || "-",
    // Native plugins are libraries other developers sign: the hardened runtime
    // loads them only with library validation off (docs/adr/0017-macos-library-validation.md).
    entitlements: entitlements || "assets/entitlements.plist",
    notarize: env.NOTARY_KEYCHAIN ? { keychainProfile: "notary", keychain: env.NOTARY_KEYCHAIN } : undefined,
  },
  windows: { signCommand: env.WINDOWS_SIGN_COMMAND },
  // 通过本 Fork 仓库的 GitHub Releases 分发软件内自动更新，
  // 对应的签名私钥保存在仓库 Actions Secret MYGO_UPDATER_PRIVATE_KEY 中。
  updates: {
    publicKey: "SmQx/Qg3FxUIuhPQ7rQkgT1uc3cgfmghUTu9QqSCi40=",
    github: "jhzhang09/godwit",
  },
};
