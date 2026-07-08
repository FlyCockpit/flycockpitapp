import { Label } from "@flycockpit/ui/components/label";
import { Textarea } from "@flycockpit/ui/components/textarea";
import { cn } from "@flycockpit/ui/lib/utils";
import { Eye, Pencil } from "lucide-react";
import { useId, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import Markdown, { defaultUrlTransform } from "react-markdown";

/**
 * Two-pane (desktop) / tabbed (mobile) markdown editor with a live preview.
 *
 * Image embeds use the `asset:<id>` URI scheme — when the preview encounters
 * `![alt](asset:abc123)` it rewrites the URL to `/api/images/abc123` so the
 * preview shows the same artwork the rendered article will. Every resulting
 * URL still flows through react-markdown's default sanitizer.
 */
export interface MarkdownEditorProps {
  value: string;
  onChange: (next: string) => void;
  onBlur?: () => void;
  label?: string;
  placeholder?: string;
  rows?: number;
  /** Width hint forwarded into `/api/images/:id?w=...` for inline embeds. */
  previewImageWidth?: number;
  className?: string;
  id?: string;
  name?: string;
  disabled?: boolean;
  required?: boolean;
}

const ASSET_PREFIX = "asset:";

function rewriteAssetUrl(url: string, w: number) {
  if (!url.startsWith(ASSET_PREFIX)) return url;
  const id = url.slice(ASSET_PREFIX.length).split(/[?#]/, 1)[0];
  if (!id) return url;
  return `/api/images/${id}?w=${w}&format=webp`;
}

export function MarkdownEditor({
  value,
  onChange,
  onBlur,
  label,
  placeholder,
  rows = 16,
  previewImageWidth = 800,
  className,
  id,
  name,
  disabled,
  required,
}: MarkdownEditorProps) {
  const reactId = useId();
  const fieldId = id ?? `markdown-${reactId}`;
  const [mobileTab, setMobileTab] = useState<"edit" | "preview">("edit");
  const { t } = useTranslation("admin");

  const textarea = (
    <Textarea
      id={fieldId}
      name={name}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onBlur={onBlur}
      placeholder={placeholder ?? t("markdown.editorPlaceholder")}
      rows={rows}
      disabled={disabled}
      required={required}
      // Mono font so column markdown lines up; preserve indentation.
      className="h-full min-h-64 resize-none font-mono text-sm leading-6"
      spellCheck
    />
  );

  const preview = (
    <div
      aria-live="polite"
      className="markdown-preview h-full overflow-y-auto rounded-md border bg-background p-4 text-sm leading-6"
      data-slot="markdown-preview"
    >
      {value.trim() === "" ? (
        <p className="text-sm text-muted-foreground">{t("markdown.nothingToPreview")}</p>
      ) : (
        <Markdown
          urlTransform={(url) => defaultUrlTransform(rewriteAssetUrl(url, previewImageWidth))}
          components={{
            h1: ({ children, ...p }) => (
              <h1 className="mt-4 mb-2 text-2xl font-semibold tracking-tight" {...p}>
                {children}
              </h1>
            ),
            h2: ({ children, ...p }) => (
              <h2 className="mt-4 mb-2 text-xl font-semibold tracking-tight" {...p}>
                {children}
              </h2>
            ),
            h3: ({ children, ...p }) => (
              <h3 className="mt-3 mb-2 text-lg font-semibold" {...p}>
                {children}
              </h3>
            ),
            p: (p) => <p className="my-2 leading-7" {...p} />,
            ul: (p) => <ul className="my-2 ml-5 list-disc space-y-1" {...p} />,
            ol: (p) => <ol className="my-2 ml-5 list-decimal space-y-1" {...p} />,
            li: (p) => <li className="leading-6" {...p} />,
            a: (p) => (
              <a
                className="text-primary underline underline-offset-2 hover:no-underline"
                target="_blank"
                rel="noopener noreferrer"
                {...p}
              />
            ),
            blockquote: (p) => (
              <blockquote
                className="my-2 border-l-2 border-border pl-3 text-muted-foreground"
                {...p}
              />
            ),
            code: (p) => <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs" {...p} />,
            pre: (p) => (
              <pre
                className="my-2 overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs"
                {...p}
              />
            ),
            // Force lazy loading + intrinsic styles so big embeds don't blow
            // out the preview pane.
            img: ({ alt, src }) => (
              <img
                alt={alt ?? ""}
                src={typeof src === "string" ? src : undefined}
                loading="lazy"
                className="my-2 max-h-80 w-auto max-w-full rounded-md"
              />
            ),
          }}
        >
          {value}
        </Markdown>
      )}
    </div>
  );

  return (
    <div className={cn("space-y-2", className)}>
      {label && <Label htmlFor={fieldId}>{label}</Label>}

      {/* Mobile: tabs. Hidden ≥md. */}
      <div className="md:hidden">
        <div role="tablist" aria-label={t("markdown.editorViewLabel")} className="flex gap-1">
          <TabButton
            active={mobileTab === "edit"}
            onClick={() => setMobileTab("edit")}
            icon={<Pencil className="size-3.5" />}
          >
            {t("markdown.edit")}
          </TabButton>
          <TabButton
            active={mobileTab === "preview"}
            onClick={() => setMobileTab("preview")}
            icon={<Eye className="size-3.5" />}
          >
            {t("markdown.preview")}
          </TabButton>
        </div>
        <div className="mt-2">{mobileTab === "edit" ? textarea : preview}</div>
      </div>

      {/* Desktop: side-by-side. */}
      <div className="hidden gap-3 md:grid md:grid-cols-2">
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-muted-foreground">{t("markdown.edit")}</span>
          {textarea}
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-muted-foreground">{t("markdown.preview")}</span>
          {preview}
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        <Trans i18nKey="markdown.assetEmbedHint" t={t} components={[<code key="0" />]} />
      </p>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={cn(
        "inline-flex min-h-[44px] flex-1 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium",
        active
          ? "border-primary/40 bg-muted text-foreground"
          : "border-transparent text-muted-foreground hover:bg-muted",
      )}
    >
      {icon}
      {children}
    </button>
  );
}
