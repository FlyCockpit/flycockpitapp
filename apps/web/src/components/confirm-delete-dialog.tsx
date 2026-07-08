import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@flycockpit/ui/components/alert-dialog";
import { Button } from "@flycockpit/ui/components/button";
import { Input } from "@flycockpit/ui/components/input";
import { Label } from "@flycockpit/ui/components/label";
import { Copy } from "lucide-react";
import type * as React from "react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

type ConfirmDeleteDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: React.ReactNode;
  /** Verbatim string the admin must type to enable the destructive action. */
  confirmToken: string;
  /** Label rendered above the typed input, e.g. "Type the user's email to confirm". */
  typePrompt: string;
  /** aria-label for the copy-to-clipboard button (i18n owns this string). */
  copyAriaLabel: string;
  /** Defaults to confirmToken. */
  placeholder?: string;
  inputMode?: React.HTMLAttributes<HTMLInputElement>["inputMode"];
  /** Defaults to t("common:actions.delete"). */
  confirmLabel?: string;
  /** Defaults to t("common:actions.deleting"). */
  pendingLabel?: string;
  isPending?: boolean;
  /** Extra disable signal OR'd with the built-in checks (e.g. count === 0 for bulk). */
  disabled?: boolean;
  /**
   * Called with the operator's *typed* value (guaranteed === confirmToken,
   * since the action is disabled until they match). Pass it through to the
   * server so the confirmation reflects deliberate keystrokes rather than a
   * value the client copied back from its own fetched state.
   */
  onConfirm: (confirmValue: string) => void;
};

export function ConfirmDeleteDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmToken,
  typePrompt,
  copyAriaLabel,
  placeholder,
  inputMode,
  confirmLabel,
  pendingLabel,
  isPending = false,
  disabled = false,
  onConfirm,
}: ConfirmDeleteDialogProps) {
  const [confirm, setConfirm] = useState("");
  const inputId = useId();
  const { t } = useTranslation("common");

  const handleOpenChange = (next: boolean) => {
    if (!next) setConfirm("");
    onOpenChange(next);
  };

  const matches = confirm === confirmToken && confirmToken.length > 0;
  const actionDisabled = !matches || isPending || disabled;

  return (
    <AlertDialog open={open} onOpenChange={handleOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <div className="space-y-2 px-4 sm:px-6">
          <Label htmlFor={inputId}>{typePrompt}</Label>
          <div className="flex items-center gap-2">
            <code className="flex-1 truncate rounded bg-muted px-2 py-1 font-mono text-sm">
              {confirmToken}
            </code>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              className="min-h-[44px] min-w-[44px]"
              onClick={() => navigator.clipboard.writeText(confirmToken)}
              aria-label={copyAriaLabel}
              disabled={!confirmToken}
            >
              <Copy className="size-4" />
            </Button>
          </div>
          <Input
            id={inputId}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder={placeholder ?? confirmToken}
            autoComplete="off"
            inputMode={inputMode}
          />
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel className="min-h-[44px]">{t("actions.cancel")}</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            className="min-h-[44px]"
            disabled={actionDisabled}
            onClick={() => onConfirm(confirm)}
          >
            {isPending
              ? (pendingLabel ?? t("actions.deleting"))
              : (confirmLabel ?? t("actions.delete"))}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
