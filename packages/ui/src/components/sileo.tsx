import { useTheme } from "next-themes";
import { Toaster as SileoToaster, sileo } from "sileo";
import "sileo/styles.css";

interface ToasterProps {
  position?:
    | "top-left"
    | "top-center"
    | "top-right"
    | "bottom-left"
    | "bottom-center"
    | "bottom-right";
}

const Toaster = ({ position = "bottom-center", ...props }: ToasterProps) => {
  const { resolvedTheme } = useTheme();

  return (
    <SileoToaster
      theme={(resolvedTheme as "light" | "dark") ?? "system"}
      position={position}
      {...props}
    />
  );
};

type ToastOptions = {
  duration?: number;
  action?: {
    label: string;
    onClick: () => void;
  };
};

function createToastMethod(method: "success" | "error" | "info" | "warning") {
  return (message: string, options?: ToastOptions) => {
    return sileo[method]({
      title: message,
      ...(options?.duration != null ? { duration: options.duration } : {}),
      ...(options?.action
        ? { button: { title: options.action.label, onClick: options.action.onClick } }
        : {}),
    });
  };
}

const toast = {
  success: createToastMethod("success"),
  error: createToastMethod("error"),
  info: createToastMethod("info"),
  warning: createToastMethod("warning"),
  dismiss: sileo.dismiss,
  clear: sileo.clear,
};

export { Toaster, toast };
