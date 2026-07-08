import { useEffect, useRef, useState } from "react";

const MD_BREAKPOINT = 768;

export function useMobileKeyboard() {
  const [inputFocused, setInputFocused] = useState(false);
  const [keyboardOpen, setKeyboardOpen] = useState(false);
  const initialHeight = useRef(0);

  useEffect(() => {
    const isEditable = (el: HTMLElement) => {
      const tag = el.tagName;
      return (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        el.isContentEditable ||
        el.getAttribute("role") === "textbox"
      );
    };

    const onFocusIn = (e: FocusEvent) => {
      if (
        window.innerWidth < MD_BREAKPOINT &&
        e.target instanceof HTMLElement &&
        isEditable(e.target)
      ) {
        setInputFocused(true);
      }
    };
    const onFocusOut = (e: FocusEvent) => {
      if (e.target instanceof HTMLElement && isEditable(e.target)) {
        setInputFocused(false);
      }
    };
    document.addEventListener("focusin", onFocusIn);
    document.addEventListener("focusout", onFocusOut);
    return () => {
      document.removeEventListener("focusin", onFocusIn);
      document.removeEventListener("focusout", onFocusOut);
    };
  }, []);

  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;
    initialHeight.current = vv.height;

    const check = () => {
      const baseline = initialHeight.current || window.innerHeight;
      setKeyboardOpen(vv.height < baseline * 0.8);
    };

    vv.addEventListener("resize", check);
    vv.addEventListener("scroll", check, { passive: true });
    return () => {
      vv.removeEventListener("resize", check);
      vv.removeEventListener("scroll", check);
    };
  }, []);

  return inputFocused || keyboardOpen;
}
