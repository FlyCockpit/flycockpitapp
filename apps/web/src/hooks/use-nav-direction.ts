import { useRouter } from "@tanstack/react-router";

import { getNavDirection, stripLangPrefix } from "@/lib/nav-items";

import { useMountEffect } from "./use-mount-effect";

export function useNavDirection() {
  const router = useRouter();

  useMountEffect(() => {
    const unsubscribeBefore = router.subscribe(
      "onBeforeNavigate",
      ({ fromLocation, toLocation }) => {
        const from = fromLocation ? stripLangPrefix(fromLocation.pathname) : "";
        const to = stripLangPrefix(toLocation.pathname);
        const direction = from === "" ? "forward" : getNavDirection(from, to);

        document.documentElement.setAttribute("data-nav-direction", direction);
      },
    );

    // Reset once navigation resolves so the forward/back slide styling only
    // applies during an active navigation and never inherits a stale value.
    const unsubscribeResolved = router.subscribe("onResolved", () => {
      document.documentElement.setAttribute("data-nav-direction", "none");
    });

    return () => {
      unsubscribeBefore();
      unsubscribeResolved();
    };
  });
}
