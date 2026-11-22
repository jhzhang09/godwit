import {
  RiAlertLine,
  RiEyeLine,
  RiKey2Line,
  RiLockFill,
  RiLockUnlockLine,
  RiRefreshLine,
  RiShieldCheckFill,
  RiShieldLine,
  RiUploadLine,
} from "@remixicon/react";
import { cn } from "cn";
import { useState } from "react";
import { Button } from "@/components/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from "@/components/ui/popover";
import type { ComposeSMIME, ComposeSMIMECert } from "@/mygo";
import type { T } from "@/shared/i18n";
import {
  certViewFromOwnIdentity,
  certViewFromRecipientCert,
  SmimeCertDialog,
  type SmimeCertView,
} from "./SmimeCertDialog";

function formatShortDate(ms: number): string {
  if (!ms) return "";
  return new Date(ms).toISOString().slice(0, 10);
}

function sourceLabel(t: T, source: string): string {
  const key = `smime.source.${source}`;
  const label = t(key);
  return label !== key ? label : source;
}

function formatCertSummary(c: ComposeSMIMECert, addr: string, t: T): string {
  const exp = c.notAfter ? t("smime.compose.expires", formatShortDate(c.notAfter)) : "";
  const trustNote = c.trusted ? "" : ` (${t("smime.cert.untrusted")})`;
  const parts = [c.subject || addr, sourceLabel(t, c.source)];
  if (exp) parts.push(exp);
  return parts.join(" · ") + trustNote;
}

function ownErrorText(smime: ComposeSMIME, t: T): string {
  if (smime.ownErrorCode) return t(`smime.err.${smime.ownErrorCode}`, smime.from);
  return smime.ownError ?? "";
}

function recipientErrorText(
  address: string,
  errorCode: string | undefined,
  error: string | undefined,
  t: T,
): string {
  if (errorCode) {
    const headline = t(`smime.err.${errorCode}`, address);
    if (error && error !== headline) return `${headline} (${error})`;
    return headline;
  }
  return error ?? "";
}

export function SmimeBar({
  smime,
  busy,
  loading = false,
  hasRecipients = false,
  t,
  onOpen,
  onRefresh,
  onToggleSign,
  onToggleEncrypt,
  onPinCert,
  onImportCert,
}: {
  smime?: ComposeSMIME;
  busy: boolean;
  loading?: boolean;
  hasRecipients?: boolean;
  t: T;
  onOpen(): void;
  onRefresh?: () => void;
  onToggleSign(on: boolean): void;
  onToggleEncrypt(on: boolean): void;
  onPinCert(address: string, sha256: string): void;
  onImportCert(address: string): void;
}) {
  const [open, setOpen] = useState(false);
  const [viewingCert, setViewingCert] = useState<SmimeCertView | null>(null);

  if (!smime?.supported) return null;

  const signIssue = smime.sign && !smime.canSendSigned;
  const encryptIssue = smime.encrypt && !smime.canSendEncrypted;
  const rcpts = smime.recipients ?? [];
  const readyCount = rcpts.filter((r) => r.ready).length;
  const hasCertIssue = signIssue || encryptIssue || rcpts.some((r) => !r.ready);

  const activeOwnCert =
    smime.ownCerts.find((c) =>
      smime.ownCertSha ? c.sha256 === smime.ownCertSha : c.canSign || c.canEncrypt,
    ) ?? smime.ownCerts[0];
  const ownErr = ownErrorText(smime, t);

  const inspectCert = (v: SmimeCertView) => {
    setOpen(false);
    setViewingCert(v);
  };

  return (
    <>
      <div className="ml-auto flex items-center gap-1" data-testid="smime-bar">
        <Button
          type="button"
          size="sm"
          variant={smime.sign ? "secondary" : "ghost"}
          disabled={busy}
          aria-pressed={smime.sign}
          title={t("smime.compose.sign_tip")}
          className={cn(
            "h-7 gap-1 px-2 text-xs",
            !smime.sign && !signIssue && "text-muted-foreground",
            signIssue && "text-destructive ring-1 ring-destructive/40",
          )}
          onClick={() => onToggleSign(!smime.sign)}
        >
          {smime.sign ? (
            <RiShieldCheckFill className="size-3.5" />
          ) : (
            <RiShieldLine className="size-3.5" />
          )}
          <span>{t("smime.compose.sign")}</span>
          {signIssue && <RiAlertLine className="size-3" />}
        </Button>

        <Button
          type="button"
          size="sm"
          variant={smime.encrypt ? "secondary" : "ghost"}
          disabled={busy}
          aria-pressed={smime.encrypt}
          title={t("smime.compose.encrypt_tip")}
          className={cn(
            "h-7 gap-1 px-2 text-xs",
            !smime.encrypt && !encryptIssue && "text-muted-foreground",
            encryptIssue && "text-destructive ring-1 ring-destructive/40",
          )}
          onClick={() => onToggleEncrypt(!smime.encrypt)}
        >
          {smime.encrypt ? (
            <RiLockFill className="size-3.5" />
          ) : (
            <RiLockUnlockLine className="size-3.5" />
          )}
          <span>{t("smime.compose.encrypt")}</span>
          {encryptIssue && <RiAlertLine className="size-3" />}
        </Button>

        <Popover
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            if (next) onOpen();
          }}
        >
          <PopoverTrigger
            render={
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={busy}
                aria-label={t("smime.compose.certs")}
                title={t("smime.compose.certs")}
                className={cn(
                  "h-7 gap-1 px-2 text-xs text-muted-foreground",
                  (signIssue || encryptIssue) && "text-destructive",
                )}
              />
            }
          >
            <RiKey2Line className="size-3.5" />
            {rcpts.length > 0 && (
              <span className="tabular-nums">
                {readyCount}/{rcpts.length}
              </span>
            )}
            {hasCertIssue && (smime.sign || smime.encrypt) && (
              <RiAlertLine className="size-3 text-destructive" />
            )}
          </PopoverTrigger>

          <PopoverContent side="top" align="end" className="w-[26rem] max-h-96 overflow-y-auto p-3">
            <PopoverHeader>
              <PopoverTitle className="flex items-center justify-between gap-2 text-xs font-semibold">
                <span>{t("smime.compose.certs")}</span>
                <div className="flex items-center gap-1.5">
                  {rcpts.length > 0 && (
                    <span className="font-normal text-muted-foreground">
                      {readyCount === rcpts.length
                        ? t("smime.compose.certs_ready")
                        : t("smime.compose.certs_missing")}
                    </span>
                  )}
                  {onRefresh && (
                    <Button
                      type="button"
                      size="xs"
                      variant="ghost"
                      disabled={loading || busy}
                      aria-label={t("smime.cert.refresh")}
                      title={t("smime.cert.refresh")}
                      className="h-5 gap-1 px-1.5 text-[11px] font-normal text-muted-foreground"
                      onClick={onRefresh}
                    >
                      <RiRefreshLine className={cn("size-3", loading && "animate-spin")} />
                      <span>{t("smime.cert.refresh")}</span>
                    </Button>
                  )}
                </div>
              </PopoverTitle>
            </PopoverHeader>

            <div className="flex flex-col gap-3 text-xs">
              <div className="rounded-md border border-border/70 bg-muted/30 p-2">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="font-medium text-muted-foreground">
                    {t("smime.compose.own_title")}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <Badge
                      variant={smime.ownReady ? "secondary" : "destructive"}
                      className="h-4 px-1.5 text-[10px]"
                    >
                      {smime.ownReady
                        ? t("smime.compose.own_ready")
                        : t("smime.compose.own_missing")}
                    </Badge>
                    {activeOwnCert && (
                      <Button
                        type="button"
                        size="xs"
                        variant="outline"
                        className="h-5 gap-1 px-1.5 text-[11px]"
                        onClick={() =>
                          inspectCert(certViewFromOwnIdentity(activeOwnCert, smime.from, t, ownErr))
                        }
                      >
                        <RiEyeLine className="size-3" />
                        <span>{t("smime.cert.view")}</span>
                      </Button>
                    )}
                  </div>
                </div>
                <div className="truncate font-medium">{smime.from}</div>
                {activeOwnCert && (
                  <div className="mt-0.5 truncate text-muted-foreground">
                    {activeOwnCert.subject} ·{" "}
                    {t(activeOwnCert.hardware ? "smime.cert.hardware" : "smime.cert.software")}
                    {activeOwnCert.notAfter
                      ? ` · ${t("smime.compose.expires", formatShortDate(activeOwnCert.notAfter))}`
                      : ""}
                  </div>
                )}
                {ownErr && (!activeOwnCert || !smime.ownReady) && (
                  <div className="mt-1 text-destructive">{ownErr}</div>
                )}
              </div>

              <div className="flex flex-col gap-2">
                <div className="font-medium text-muted-foreground">
                  {t("smime.compose.rcpts_title")}
                </div>
                {rcpts.length === 0 ? (
                  <div className="rounded-md border border-dashed border-border/70 p-2.5 text-muted-foreground">
                    {loading || hasRecipients
                      ? t("smime.compose.rcpts_loading")
                      : t("smime.compose.rcpts_empty")}
                  </div>
                ) : (
                  rcpts.map((r) => {
                    const pinnedCert = r.certs.find((c) => c.selected);
                    const selectedSha = pinnedCert?.sha256 ?? "";
                    const autoCert = r.certs.find((c) => c.sha256 === r.selected);
                    const activeCert = pinnedCert ?? autoCert ?? r.certs[0];
                    const autoOptionLabel = autoCert
                      ? t("smime.cert.auto_selected", formatCertSummary(autoCert, r.address, t))
                      : t("smime.cert.auto");
                    const rcptErr = recipientErrorText(r.address, r.errorCode, r.error, t);
                    return (
                      <div
                        key={r.address}
                        className="flex flex-col gap-1.5 rounded-md border border-border/70 p-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-medium">{r.address}</span>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <Badge
                              variant={r.ready ? "secondary" : "destructive"}
                              className="h-4 px-1.5 text-[10px]"
                            >
                              {t(
                                r.ready ? "smime.compose.rcpt_ready" : "smime.compose.rcpt_missing",
                              )}
                            </Badge>
                            <Button
                              type="button"
                              size="xs"
                              variant="outline"
                              disabled={busy}
                              className="h-6 gap-1 px-2 text-[11px]"
                              onClick={() => onImportCert(r.address)}
                            >
                              <RiUploadLine className="size-3" />
                              <span>{t("smime.compose.rcpt_import")}</span>
                            </Button>
                          </div>
                        </div>

                        {r.certs.length > 0 && (
                          <div className="flex items-center gap-1.5">
                            <select
                              aria-label={r.address}
                              disabled={busy}
                              value={selectedSha}
                              onChange={(e) => onPinCert(r.address, e.target.value)}
                              className="h-7 min-w-0 flex-1 rounded-md border border-input bg-background px-2 text-xs outline-hidden focus-visible:border-ring focus-visible:ring-1 focus-visible:ring-ring"
                            >
                              <option value="">{autoOptionLabel}</option>
                              {r.certs.map((c) => (
                                <option key={c.sha256} value={c.sha256}>
                                  {formatCertSummary(c, r.address, t)}
                                </option>
                              ))}
                            </select>
                            {activeCert && (
                              <Button
                                type="button"
                                size="xs"
                                variant="outline"
                                className="h-7 shrink-0 gap-1 px-2 text-[11px]"
                                onClick={() =>
                                  inspectCert(certViewFromRecipientCert(activeCert, t))
                                }
                              >
                                <RiEyeLine className="size-3" />
                                <span>{t("smime.cert.view")}</span>
                              </Button>
                            )}
                          </div>
                        )}

                        {!r.ready && rcptErr && (
                          <div className="text-[11px] text-destructive">{rcptErr}</div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </div>

      <SmimeCertDialog
        cert={viewingCert}
        onOpenChange={(next) => {
          if (!next) setViewingCert(null);
        }}
        t={t}
      />
    </>
  );
}
