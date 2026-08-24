// Lets a page publish its header subtitle and action buttons up into the shell.
//
// The Access v3 design puts per-screen actions in the shared 54px header
// ("Scanner une carte" + "Synchroniser" on the dashboard, "Recharger" +
// "Synchroniser" on Appareils…), but the header is owned by MainLayout while
// the actions belong to the page. React Router's <Outlet context> only flows
// parent → child, so this small context carries the value the other way.

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export interface PageChrome {
  /** Muted line rendered beside the page title (e.g. "Entrée principale · 09:43"). */
  subtitle?: ReactNode;
  /** Buttons rendered on the right of the header. */
  actions?: ReactNode;
  /**
   * Full-height page that manages its own scrolling (the dashboard's feed and
   * rail each scroll internally). When false — the default — the shell scrolls
   * the whole page, which is what every existing screen expects.
   */
  fill?: boolean;
}

interface PageChromeCtx {
  chrome: PageChrome;
  setChrome: (chrome: PageChrome) => void;
}

const Ctx = createContext<PageChromeCtx | null>(null);

export function PageChromeProvider({ children }: { children: ReactNode }) {
  const [chrome, setChrome] = useState<PageChrome>({});
  const value = useMemo(() => ({ chrome, setChrome }), [chrome]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Read the current page's chrome — used by MainLayout's header. */
export function usePageChromeValue(): PageChrome {
  return useContext(Ctx)?.chrome ?? {};
}

/**
 * Publish this page's header chrome.
 *
 * `build` re-runs only when `deps` change, so pass every value the returned
 * nodes close over. The dep array is deliberately manual: the nodes are new
 * objects on every render, so keying the effect on them would set state each
 * render and loop forever.
 */
export function usePageChrome(build: () => PageChrome, deps: unknown[]): void {
  const setChrome = useContext(Ctx)?.setChrome;
  useEffect(() => {
    if (!setChrome) return;
    setChrome(build());
    // Clear on unmount so the next page never inherits stale buttons. React
    // unmounts the outgoing route before mounting the incoming one, so this
    // cleanup cannot wipe the next page's chrome.
    return () => setChrome({});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setChrome, ...deps]);
}
