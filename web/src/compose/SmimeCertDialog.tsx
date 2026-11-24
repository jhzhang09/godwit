import {
  RiAlertLine,
  RiCheckboxCircleLine,
  RiCheckLine,
  RiCloseCircleLine,
  RiFileCopyLine,
} from "@remixicon/react";
import { useEffect, useState } from "react";
import { Button } from "@/components/button";
import {
  Dialog,
  DialogCancel,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/dialog";
import { Badge } from "@/components/ui/badge";
import type { ComposeSMIMECert, ComposeSMIMECertChainNode, ComposeSMIMEIdentity } from "@/mygo";
import type { T } from "@/shared/i18n";

export interface SmimeCertView {
  subject: string;
  subjectDn?: string;
  issuer: string;
  issuerDn?: string;
  emails: string[];
  serialNumber?: string;
  notBefore: number;
  notAfter: number;
  publicKeyAlgo?: string;
  signatureAlgo?: string;
  keyUsages: string[];
  extKeyUsages: string[];
  sha256: string;
  sha1?: string;
  sourceLabel?: string;
  trusted: boolean;
  trustErr?: string;
  chain?: ComposeSMIMECertChainNode[];
}

export function formatFingerprintHex(hex?: string): string {
  const clean = (hex ?? "").trim().toUpperCase();
  if (!clean) return "";
  if (clean.includes(":")) return clean;
  const pairs: string[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    pairs.push(clean.slice(i, i + 2));
  }
  return pairs.join(":");
}

function formatDateTime(ms: number): string {
  if (!ms) return "";
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function formatUsages(keyUsages: string[], extKeyUsages: string[], t: T): string {
  const out: string[] = [];
  for (const u of [...keyUsages, ...extKeyUsages]) {
    const key = `smime.usage.${u}`;
    const label = t(key);
    out.push(label !== key ? label : u);
  }
  return out.join(" · ");
}

export function certViewFromRecipientCert(c: ComposeSMIMECert, t: T): SmimeCertView {
  const srcKey = `smime.source.${c.source}`;
  const srcLabel = t(srcKey);
  return {
    subject: c.subject || c.address,
    subjectDn: c.subjectDn,
    issuer: c.issuer,
    issuerDn: c.issuerDn,
    emails: c.emails?.length ? c.emails : c.address ? [c.address] : [],
    serialNumber: c.serialNumber,
    notBefore: c.notBefore,
    notAfter: c.notAfter,
    publicKeyAlgo: c.publicKeyAlgo,
    signatureAlgo: c.signatureAlgo,
    keyUsages: c.keyUsages ?? [],
    extKeyUsages: c.extKeyUsages ?? [],
    sha256: c.sha256,
    sha1: c.sha1,
    sourceLabel: srcLabel !== srcKey ? srcLabel : c.source,
    trusted: c.trusted,
    trustErr: c.trustErr,
    chain: c.chain,
  };
}

export function certViewFromOwnIdentity(
  id: ComposeSMIMEIdentity,
  from: string,
  t: T,
  ownErr?: string,
): SmimeCertView {
  return {
    subject: id.subject || from,
    subjectDn: id.subjectDn,
    issuer: id.issuer,
    issuerDn: id.issuerDn,
    emails: id.emails?.length ? id.emails : from ? [from] : [],
    serialNumber: id.serialNumber,
    notBefore: id.notBefore,
    notAfter: id.notAfter,
    publicKeyAlgo: id.publicKeyAlgo,
    signatureAlgo: id.signatureAlgo,
    keyUsages: id.keyUsages ?? [],
    extKeyUsages: id.extKeyUsages ?? [],
    sha256: id.sha256,
    sha1: id.sha1,
    sourceLabel: t(id.hardware ? "smime.cert.hardware" : "smime.cert.software"),
    trusted: id.canSign || id.canEncrypt,
    trustErr: ownErr,
    chain: id.chain,
  };
}

function DetailRow({
  label,
  value,
  sub,
  mono,
}: {
  label: string;
  value?: string;
  sub?: string;
  mono?: boolean;
}) {
  if (!value) return null;
  return (
    <div className="flex flex-col gap-0.5">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className={`break-all text-xs font-medium select-text ${mono ? "font-mono" : ""}`}>
        {value}
      </div>
      {sub && sub !== value && (
        <div className="break-all text-[11px] text-muted-foreground select-text">{sub}</div>
      )}
    </div>
  );
}

export function SmimeCertDialog({
  cert,
  onOpenChange,
  t,
}: {
  cert: SmimeCertView | null;
  onOpenChange(open: boolean): void;
  t: T;
}) {
  const [copiedSha, setCopiedSha] = useState("");

  useEffect(() => {
    if (!copiedSha) return;
    const id = window.setTimeout(() => setCopiedSha(""), 1800);
    return () => window.clearTimeout(id);
  }, [copiedSha]);

  if (!cert) return null;

  const expired = cert.notAfter > 0 && Date.now() > cert.notAfter;
  const validity =
    cert.notBefore && cert.notAfter
      ? `${formatDateTime(cert.notBefore)} – ${formatDateTime(cert.notAfter)}`
      : cert.notAfter
        ? formatDateTime(cert.notAfter)
        : "";
  const usages = formatUsages(cert.keyUsages, cert.extKeyUsages, t);
  const sha256Colon = formatFingerprintHex(cert.sha256);
  const sha1Colon = formatFingerprintHex(cert.sha1);
  const copied = !!sha256Colon && copiedSha === sha256Colon;
  const hasTech =
    cert.serialNumber ||
    cert.publicKeyAlgo ||
    cert.signatureAlgo ||
    usages ||
    sha256Colon ||
    sha1Colon;

  const copySha256 = async () => {
    try {
      await navigator.clipboard?.writeText(sha256Colon);
      setCopiedSha(sha256Colon);
    } catch {
      // Clipboard may be restricted in non-HTTPS test environments.
    }
  };

  const chain = cert.chain ?? [];
  const rootTrustedNode =
    cert.trusted && chain.length > 1 && chain[0]?.role === "root" ? chain[0] : undefined;
  const roleLabel = (role: string) => {
    switch (role) {
      case "root":
        return t("smime.cert.role_root");
      case "intermediate":
        return t("smime.cert.role_intermediate");
      case "leaf":
        return t("smime.cert.role_leaf");
      default:
        return role;
    }
  };

  return (
    <Dialog open={!!cert} onOpenChange={onOpenChange}>
      <DialogContent size="md" close={t("common.close")} onKeyDown={(e) => e.stopPropagation()}>
        <DialogHeader>
          <DialogTitle>{t("smime.cert.detail_title")}</DialogTitle>
          <DialogDescription>{cert.subject || cert.emails[0] || ""}</DialogDescription>
        </DialogHeader>

        <div className="flex max-h-[60vh] flex-col gap-3 overflow-y-auto pr-0.5 text-xs">
          <div
            className={`flex flex-col gap-1 rounded-lg border px-3 py-2 ${
              cert.trusted
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                : "border-amber-500/30 bg-amber-500/10 text-amber-800 dark:text-amber-300"
            }`}
          >
            <div className="flex items-center gap-2">
              {cert.trusted ? (
                <RiCheckboxCircleLine className="size-4 shrink-0" />
              ) : (
                <RiAlertLine className="size-4 shrink-0" />
              )}
              <span className="flex-1 font-medium">
                {t(cert.trusted ? "smime.cert.status_trusted" : "smime.cert.status_untrusted")}
              </span>
              {expired && (
                <Badge variant="destructive" className="h-4 px-1.5 text-[10px]">
                  {t("smime.cert.status_expired")}
                </Badge>
              )}
            </div>
            {rootTrustedNode && (
              <div className="text-[11px] opacity-90 select-text">
                {t(
                  "smime.cert.trusted_via_root",
                  rootTrustedNode.subject || rootTrustedNode.issuer,
                )}
              </div>
            )}
            {!cert.trusted && cert.trustErr && (
              <div className="text-[11px] opacity-90 select-text">{cert.trustErr}</div>
            )}
          </div>

          <div className="flex flex-col gap-2.5 rounded-lg border border-border/70 bg-background/60 p-3">
            <DetailRow
              label={t("smime.cert.field_subject")}
              value={cert.subject || cert.emails[0]}
              sub={cert.subjectDn}
            />
            {cert.emails.length > 0 && (
              <DetailRow label={t("smime.cert.field_email")} value={cert.emails.join(", ")} />
            )}
            <DetailRow
              label={t("smime.cert.field_issuer")}
              value={cert.issuer}
              sub={cert.issuerDn}
            />
            <DetailRow label={t("smime.cert.field_validity")} value={validity} />
            <DetailRow label={t("smime.cert.field_source")} value={cert.sourceLabel} />
          </div>

          {chain.length > 1 && (
            <div className="flex flex-col gap-2 rounded-lg border border-border/70 bg-background/60 p-3">
              <div className="text-[11px] text-muted-foreground">{t("smime.cert.chain")}</div>
              <div className="flex flex-col gap-2">
                {chain.map((node, i) => {
                  const status = node.status || (cert.trusted ? "trusted" : "untrusted");
                  const issues = node.issues ?? [];
                  const statusBadge = (() => {
                    if (status === "trusted") {
                      const labelKey =
                        node.role === "root"
                          ? "smime.cert.root_trusted"
                          : node.role === "intermediate"
                            ? "smime.cert.chain_trusted"
                            : "smime.cert.leaf_trusted";
                      return (
                        <Badge
                          variant="secondary"
                          className="h-4 border border-emerald-500/30 bg-emerald-500/10 px-1.5 text-[10px] text-emerald-700 dark:text-emerald-300"
                        >
                          {t(labelKey)}
                        </Badge>
                      );
                    }
                    if (status === "failed") {
                      const labelKey =
                        node.role === "root" && issues.includes("untrusted_root")
                          ? "smime.cert.root_untrusted"
                          : "smime.cert.node_failed";
                      return (
                        <Badge variant="destructive" className="h-4 px-1.5 text-[10px]">
                          {t(labelKey)}
                        </Badge>
                      );
                    }
                    const labelKey =
                      i === 0 && node.role !== "root"
                        ? "smime.cert.chain_missing_root"
                        : "smime.cert.node_untrusted";
                    return (
                      <Badge
                        variant="secondary"
                        className="h-4 border border-amber-500/30 bg-amber-500/10 px-1.5 text-[10px] text-amber-800 dark:text-amber-300"
                      >
                        {t(labelKey)}
                      </Badge>
                    );
                  })();

                  return (
                    <div
                      key={node.sha256 || `${node.role}:${node.subject}:${node.issuer}`}
                      style={{ paddingLeft: `${i * 12}px` }}
                      className="flex flex-col gap-0.5"
                    >
                      <div className="flex flex-wrap items-center gap-1.5">
                        {i > 0 && <span className="text-xs text-muted-foreground">└─</span>}
                        {status === "trusted" ? (
                          <RiCheckboxCircleLine className="size-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                        ) : status === "failed" ? (
                          <RiCloseCircleLine className="size-3.5 shrink-0 text-destructive" />
                        ) : (
                          <RiAlertLine className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
                        )}
                        <span className="text-xs font-medium select-text">
                          {node.subject || node.issuer}
                        </span>
                        <Badge
                          variant="outline"
                          className="h-4 px-1.5 text-[10px] text-muted-foreground"
                        >
                          {roleLabel(node.role)}
                        </Badge>
                        {statusBadge}
                      </div>
                      {node.publicKeyAlgo && (
                        <div className={`text-[11px] text-muted-foreground ${i > 0 ? "pl-4" : ""}`}>
                          {node.publicKeyAlgo}
                        </div>
                      )}
                      {issues.length > 0 && (
                        <div
                          className={`text-[11px] text-destructive select-text ${i > 0 ? "pl-4" : ""}`}
                        >
                          {issues
                            .map((code) => t(`smime.issue.${code}`))
                            .join(t("smime.issue.sep"))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {hasTech && (
            <div className="flex flex-col gap-2.5 rounded-lg border border-border/70 bg-background/60 p-3">
              <DetailRow label={t("smime.cert.field_serial")} value={cert.serialNumber} mono />
              <DetailRow label={t("smime.cert.field_pubkey")} value={cert.publicKeyAlgo} />
              <DetailRow label={t("smime.cert.field_sigalg")} value={cert.signatureAlgo} />
              <DetailRow label={t("smime.cert.field_usage")} value={usages} />
              {sha256Colon && (
                <div className="flex flex-col gap-0.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] text-muted-foreground">
                      {t("smime.cert.field_sha256")}
                    </span>
                    <Button
                      type="button"
                      size="xs"
                      variant="ghost"
                      className="h-5 gap-1 px-1.5 text-[11px]"
                      onClick={() => void copySha256()}
                    >
                      {copied ? (
                        <>
                          <RiCheckLine className="size-3" />
                          <span>{t("smime.cert.copied")}</span>
                        </>
                      ) : (
                        <>
                          <RiFileCopyLine className="size-3" />
                          <span>{t("smime.cert.copy_fp")}</span>
                        </>
                      )}
                    </Button>
                  </div>
                  <div className="break-all font-mono text-[11px] font-medium select-text">
                    {sha256Colon}
                  </div>
                </div>
              )}
              <DetailRow label={t("smime.cert.field_sha1")} value={sha1Colon} mono />
            </div>
          )}
        </div>

        <DialogFooter>
          <DialogCancel>{t("common.close")}</DialogCancel>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
