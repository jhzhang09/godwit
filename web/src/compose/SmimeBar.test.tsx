import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ComposeSMIME } from "@/mygo";
import { makeT } from "@/shared/i18n";
import { SmimeBar } from "./SmimeBar";

afterEach(cleanup);

function makeSMIME(overrides: Partial<ComposeSMIME> = {}): ComposeSMIME {
  return {
    supported: true,
    from: "alice@example.com",
    sign: false,
    encrypt: false,
    ownReady: true,
    ownCerts: [
      {
        sha256: "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff66667777888899990000",
        sha1: "00112233445566778899aabbccddeeff00112233",
        subject: "Alice Cert",
        subjectDn: "CN=Alice Cert,O=Example Corp",
        issuer: "Example CA",
        issuerDn: "CN=Example CA,O=Example Corp",
        emails: ["alice@example.com"],
        serialNumber: "1A:2B:3C",
        notBefore: Date.UTC(2025, 0, 1),
        notAfter: Date.UTC(2027, 0, 1),
        publicKeyAlgo: "RSA (2048 bit)",
        signatureAlgo: "SHA256-RSA",
        keyUsages: ["digital_signature", "key_encipherment"],
        extKeyUsages: ["email_protection"],
        hardware: false,
        canSign: true,
        canEncrypt: true,
      },
    ],
    recipients: [
      {
        address: "bob@example.com",
        ready: true,
        selected: "bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa66667777888899990000",
        certs: [
          {
            sha256: "bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa66667777888899990000",
            sha1: "11223344556677889900aabbccddeeff11223344",
            address: "bob@example.com",
            source: "carddav",
            subject: "Bob Primary",
            subjectDn: "CN=Bob Primary",
            issuer: "Example Root CA",
            issuerDn: "CN=Example Root CA",
            emails: ["bob@example.com"],
            serialNumber: "44:55:66",
            notBefore: Date.UTC(2025, 0, 1),
            notAfter: Date.UTC(2027, 0, 1),
            publicKeyAlgo: "RSA (2048 bit)",
            signatureAlgo: "SHA256-RSA",
            keyUsages: ["key_encipherment"],
            extKeyUsages: ["email_protection"],
            trusted: true,
            selected: false,
          },
          {
            sha256: "bbbb2222",
            address: "bob@example.com",
            source: "imported",
            subject: "Bob Imported",
            issuer: "Example Root CA",
            emails: ["bob@example.com"],
            serialNumber: "77:88:99",
            notBefore: Date.UTC(2024, 0, 1),
            notAfter: Date.UTC(2026, 6, 1),
            keyUsages: ["key_encipherment"],
            extKeyUsages: [],
            trusted: true,
            selected: false,
          },
        ],
      },
      {
        address: "carol@example.com",
        ready: false,
        errorCode: "rcpt_missing",
        certs: [],
      },
    ],
    canSendSigned: true,
    canSendEncrypted: false,
    ...overrides,
  };
}

describe("SmimeBar", () => {
  const zhT = makeT("zh-Hans");
  const enT = makeT("en");

  it("renders nothing when S/MIME is unsupported", () => {
    const { container } = render(
      <SmimeBar
        smime={makeSMIME({ supported: false })}
        busy={false}
        t={zhT}
        onOpen={vi.fn()}
        onToggleSign={vi.fn()}
        onToggleEncrypt={vi.fn()}
        onPinCert={vi.fn()}
        onImportCert={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows distinct active/inactive states, auto-selected cert summary, and certificate viewer", async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    const onToggleSign = vi.fn();
    const onToggleEncrypt = vi.fn();
    const onPinCert = vi.fn();
    const onImportCert = vi.fn();

    render(
      <SmimeBar
        smime={makeSMIME({ sign: false, encrypt: true })}
        busy={false}
        t={zhT}
        onOpen={onOpen}
        onToggleSign={onToggleSign}
        onToggleEncrypt={onToggleEncrypt}
        onPinCert={onPinCert}
        onImportCert={onImportCert}
      />,
    );

    const signBtn = screen.getByRole("button", { name: "签名" });
    expect(signBtn).toHaveAttribute("aria-pressed", "false");
    expect(signBtn.className).toContain("text-muted-foreground");
    await user.click(signBtn);
    expect(onToggleSign).toHaveBeenCalledWith(true);

    const encBtn = screen.getByRole("button", { name: "加密" });
    expect(encBtn).toHaveAttribute("aria-pressed", "true");
    expect(encBtn.className).not.toContain("text-muted-foreground");
    await user.click(encBtn);
    expect(onToggleEncrypt).toHaveBeenCalledWith(false);

    // Popover trigger shows recipient readiness 1/2
    const certsBtn = screen.getByRole("button", { name: "S/MIME 证书" });
    expect(certsBtn).toHaveTextContent("1/2");
    await user.click(certsBtn);
    expect(onOpen).toHaveBeenCalled();

    // Auto-selected certificate summary is visible directly inside the selector
    const select = screen.getByLabelText("bob@example.com") as HTMLSelectElement;
    expect(select.options[0].textContent).toBe("Bob Primary · 通讯录名片 · 至 2027-01-01（自动）");

    // Selecting a specific certificate for bob@example.com pins its SHA-256
    fireEvent.change(select, { target: { value: "bbbb2222" } });
    expect(onPinCert).toHaveBeenCalledWith("bob@example.com", "bbbb2222");

    // Clicking import for carol@example.com triggers onImportCert and shows localized errorCode
    const importButtons = screen.getAllByRole("button", { name: "导入证书" });
    expect(importButtons).toHaveLength(2);
    await user.click(importButtons[1]);
    expect(onImportCert).toHaveBeenCalledWith("carol@example.com");
    expect(screen.getByText("缺少 carol@example.com 的可用 S/MIME 证书")).toBeInTheDocument();

    // Clicking View certificate for recipient opens full X.509 certificate details modal
    const viewButtons = screen.getAllByRole("button", { name: "查看证书" });
    expect(viewButtons).toHaveLength(2); // sender + bob
    await user.click(viewButtons[1]);
    expect(screen.getByText("证书详情")).toBeInTheDocument();
    expect(screen.getByText("Example Root CA")).toBeInTheDocument();
    expect(screen.getByText("44:55:66")).toBeInTheDocument();
    expect(screen.getByText("RSA (2048 bit)")).toBeInTheDocument();
    expect(
      screen.getByText(
        "BB:BB:11:11:CC:CC:22:22:DD:DD:33:33:EE:EE:44:44:FF:FF:55:55:AA:AA:66:66:77:77:88:88:99:99:00:00",
      ),
    ).toBeInTheDocument();

    await user.click(screen.getAllByRole("button", { name: "关闭" })[0]);

    // Re-open popover and inspect sender certificate
    await user.click(screen.getByRole("button", { name: "S/MIME 证书" }));
    await user.click(screen.getAllByRole("button", { name: "查看证书" })[0]);
    expect(screen.getByText("证书详情")).toBeInTheDocument();
    expect(screen.getByText("Example CA")).toBeInTheDocument();
    expect(screen.getByText("1A:2B:3C")).toBeInTheDocument();
  });

  it("renders standard localized English catalog strings and own/recipient error codes", async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn();

    render(
      <SmimeBar
        smime={makeSMIME({
          sign: true,
          ownReady: false,
          ownErrorCode: "own_missing",
          ownCerts: [],
          recipients: [
            { address: "carol@example.com", ready: false, errorCode: "rcpt_missing", certs: [] },
          ],
        })}
        busy={false}
        loading={true}
        hasRecipients={true}
        t={enT}
        onOpen={vi.fn()}
        onRefresh={onRefresh}
        onToggleSign={vi.fn()}
        onToggleEncrypt={vi.fn()}
        onPinCert={vi.fn()}
        onImportCert={vi.fn()}
      />,
    );

    const signBtn = screen.getByRole("button", { name: "Sign" });
    expect(signBtn).toHaveAttribute("aria-pressed", "true");
    await user.click(screen.getByRole("button", { name: "S/MIME Certificates" }));

    expect(
      screen.getByText("No personal S/MIME certificate found for alice@example.com"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("No usable S/MIME certificate found for carol@example.com"),
    ).toBeInTheDocument();
    const refreshBtn = screen.getByRole("button", { name: "Refresh" });
    expect(refreshBtn).toBeDisabled();
  });

  it("shows loading prompt when recipients exist before status arrives", async () => {
    const user = userEvent.setup();
    render(
      <SmimeBar
        smime={makeSMIME({ sign: false, recipients: [] })}
        busy={false}
        loading={true}
        hasRecipients={true}
        t={zhT}
        onOpen={vi.fn()}
        onRefresh={vi.fn()}
        onToggleSign={vi.fn()}
        onToggleEncrypt={vi.fn()}
        onPinCert={vi.fn()}
        onImportCert={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: "S/MIME 证书" }));
    expect(screen.getByText("正在检查收件人证书…")).toBeInTheDocument();
  });
});
