import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { lazy, Suspense } from "react";

/**
 * `qrcode.react` ships its own SVG-path encoder that is only ever needed during
 * 2FA enrollment — a path the vast majority of sessions never hit. `React.lazy`
 * splits it into its own chunk so it loads the moment a QR actually renders,
 * not when the (already route-split) security page mounts. This is the
 * component-level escape hatch for code-splitting; routes split automatically,
 * so reach for `lazy()` only for heavy widgets gated behind a rare interaction.
 * See the component-level dynamic import policy.
 */
const QRCodeSVG = lazy(() => import("qrcode.react").then((m) => ({ default: m.QRCodeSVG })));

export function LazyQRCode({ value, size }: { value: string; size: number }) {
  return (
    <Suspense fallback={<Skeleton style={{ width: size, height: size }} />}>
      <QRCodeSVG value={value} size={size} />
    </Suspense>
  );
}
