import { LazyQRCode } from "@/components/lazy-qr-code";

function secretFromTotpURI(totpURI: string) {
  if (!URL.canParse(totpURI)) return "";
  return new URL(totpURI).searchParams.get("secret") || "";
}

export function TwoFactorSetupDetails({
  totpURI,
  backupCodes,
  qrPrompt,
  manualPrompt,
  backupCodesLabel,
}: {
  totpURI: string;
  backupCodes: string[];
  qrPrompt: string;
  manualPrompt: string;
  backupCodesLabel: string;
}) {
  const secret = secretFromTotpURI(totpURI);

  return (
    <>
      {totpURI && URL.canParse(totpURI) ? (
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">{qrPrompt}</p>
          <div className="flex justify-center rounded bg-white p-4">
            <LazyQRCode value={totpURI} size={180} />
          </div>
        </div>
      ) : null}
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">{manualPrompt}</p>
        {secret ? (
          <code className="block break-all rounded bg-muted p-3 text-center font-mono text-sm">
            {secret}
          </code>
        ) : null}
      </div>

      {backupCodes.length > 0 ? (
        <div className="space-y-2">
          <p className="text-sm font-medium">{backupCodesLabel}</p>
          <div className="grid grid-cols-2 gap-1 rounded bg-muted p-3">
            {backupCodes.map((code) => (
              <code key={code} className="font-mono text-xs">
                {code}
              </code>
            ))}
          </div>
        </div>
      ) : null}
    </>
  );
}
