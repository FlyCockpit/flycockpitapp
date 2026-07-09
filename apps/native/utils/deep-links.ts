export type NativeRouteTarget =
  | {
      pathname: "/instances/[instanceId]";
      params: { instanceId: string };
    }
  | {
      pathname: "/instances/[instanceId]/projects/[projectId]";
      params: { instanceId: string; projectId: string; session?: string; interrupt?: string };
    };

function pathSegments(url: string) {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "cockpit:" && parsed.protocol !== "flycockpit:") return null;
  const hostSegment = parsed.hostname ? [parsed.hostname] : [];
  return [...hostSegment, ...parsed.pathname.split("/")].filter(Boolean).map(decodeURIComponent);
}

export function routeFromCockpitUrl(url: string): NativeRouteTarget | null {
  const segments = pathSegments(url);
  if (segments?.[0] !== "instances" || !segments[1]) return null;
  if (segments.length === 2) {
    return { pathname: "/instances/[instanceId]", params: { instanceId: segments[1] } };
  }
  if (segments[2] !== "projects" || !segments[3]) return null;
  const target: NativeRouteTarget = {
    pathname: "/instances/[instanceId]/projects/[projectId]",
    params: { instanceId: segments[1], projectId: encodeURIComponent(segments[3]) },
  };
  if (segments[4] === "sessions" && segments[5]) {
    target.params.session = segments[5];
  }
  if (segments[6] === "interrupts" && segments[7]) {
    target.params.interrupt = segments[7];
  }
  return target;
}
