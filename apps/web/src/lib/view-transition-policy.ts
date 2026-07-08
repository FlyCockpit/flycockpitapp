export type PageViewTransitionInfo = {
  pathChanged: boolean;
  hrefChanged: boolean;
  hashChanged: boolean;
};

export function getPageViewTransitionTypes(info: PageViewTransitionInfo): string[] | false {
  return info.pathChanged ? [] : false;
}
