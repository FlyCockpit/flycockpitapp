import { Button } from "@flycockpit/ui/components/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@flycockpit/ui/components/dropdown-menu";
import { Moon, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useTheme } from "@/components/theme-provider";

/**
 * The real Base UI theme menu. Lazy-loaded by `mode-toggle.tsx` on first
 * interaction so the shared Base UI overlay chunk stays off the eager bundle.
 * It mounts `defaultOpen` so the click that triggered the load opens the menu
 * immediately — no effect choreography, no second click.
 */
export default function ModeToggleMenu() {
  const { setTheme } = useTheme();
  const { t } = useTranslation("nav");

  return (
    <DropdownMenu defaultOpen>
      <DropdownMenuTrigger render={<Button variant="outline" size="icon-touch" />}>
        <Sun className="size-[1.2rem] scale-100 rotate-0 transition-transform dark:scale-0 dark:-rotate-90" />
        <Moon className="absolute size-[1.2rem] scale-0 rotate-90 transition-transform dark:scale-100 dark:rotate-0" />
        <span className="sr-only">{t("themeToggle.label")}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => setTheme("light")}>
          {t("themeToggle.light")}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme("dark")}>
          {t("themeToggle.dark")}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme("system")}>
          {t("themeToggle.system")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
