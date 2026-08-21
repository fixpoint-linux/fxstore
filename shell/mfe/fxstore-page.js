// shell/mfe/fxstore-page.js — the Elm fxstore docs page as an @mfe MFE module.
//
// Implements the @mfe/core MFE lifecycle ({ mount, unmount, update }) so the
// shell's reconcile can mount the Elm app into a [data-mfe="fxstore-page"]
// slot. This is the *client-side* twin of the build-time SSG render:
//
//   - scripts/ssg.mjs  (Node + happy-dom) loads dist/elm.js via readFileSync +
//                       indirect eval `(0, eval)(code)` to pre-render the view.
//   - this module      (browser ES module) loads dist/elm.js via fetch + the
//                       same indirect eval, so `Elm` lands on globalThis and
//                       Elm.Main.init({ node }) renders identically.
//
// dist/elm.js is a classic (non-module) IIFE script, so it cannot be `import`ed
// as an ES module; it must be run in *global* scope, which is exactly what an
// indirect eval does (its `this` is the window/globalThis). Hence fetch+eval,
// mirroring the SSG probe that validated this seam.

const ELM_URL = new URL('../../elm.js', import.meta.url).href;

// Cache the load promise so the bundle is fetched and evaluated exactly once.
let elmPromise = null;

// Every compiled Elm bundle is `(function(scope){ ... })(this)`, registering
// its modules on `scope` (defaulting to globalThis). Loading a SECOND bundle
// via indirect eval would overwrite the shared globalThis.Elm, so
// _Platform_export -> _Platform_mergeExportsProd would hit the existing
// `Main` -> `init` key and _Debug_crash(6) ("name clash"). Each MFE therefore
// evaluates its own bundle into a PRIVATE scope object, giving every Elm app
// its own `Elm` and avoiding the global collision entirely — crucial when two
// sites' MFEs load in the same shell page.
function evalBundle(code) {
  const scope = {};
  // new Function body is the bundle; calling it with .call(scope) binds the
  // bundle's `(this)` to `scope`, so Elm lands on scope.Elm, not globalThis.
  // eslint-disable-next-line no-new-func -- CSP constraints match indirect eval.
  new Function(code).call(scope);
  return scope.Elm;
}

/** Fetch + scoped-eval the compiled Elm bundle and return the Elm object. */
function loadElm() {
  if (!elmPromise) {
    elmPromise = (async () => {
      const res = await fetch(ELM_URL);
      if (!res.ok) {
        throw new Error(`fxstore-page: failed to fetch ${ELM_URL} (HTTP ${res.status})`);
      }
      const code = await res.text();
      const Elm = evalBundle(code);
      if (!Elm || !Elm.Main || typeof Elm.Main.init !== 'function') {
        throw new Error('fxstore-page: dist/elm.js did not expose Elm.Main.init');
      }
      return Elm;
    })().catch((err) => {
      // Reset so a later mount can retry instead of being permanently poisoned.
      elmPromise = null;
      throw err;
    });
  }
  return elmPromise;
}

// Tracks slot elements that already hold a live Elm app, so re-entrant mounts
// (e.g. an SSR rehydration pass) never double-initialize the same node.
const live = new WeakMap();

function clearChildren(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

/** The MFE lifecycle, per @mfe/core types.ts. */
export default {
  async mount(element, ctx) {
    if (live.has(element)) return; // already inited into this node
    const Elm = await loadElm();
    // On a fresh template the slot is empty; after SSR rehydration it already
    // holds the pre-rendered markup. Clearing first guarantees a single,
    // drift-free render from Elm regardless of which case we're in.
    clearChildren(element);
    // Elm.Main.init({node}) replaces the given node with its rendered root via
    // parentNode.replaceChild. Initializing into the [data-mfe] slot element
    // ITSELF would therefore strip the slot's data-mfe attribute and break
    // @mfe/core's reconcile slot-tracking. Mount into a fresh INNER wrapper div
    // instead: the slot element stays in the DOM (data-mfe intact) and Elm
    // replaces only the wrapper, leaving the Elm root (including the <style>
    // emitted by Fixpoint.Style.stylesheet) as the slot's child.
    const inner = document.createElement('div');
    element.appendChild(inner);
    const app = Elm.Main.init({ node: inner });
    live.set(element, app);
  },

  async unmount(element, ctx) {
    if (!live.has(element)) return;
    clearChildren(element);
    live.delete(element);
  },

  async update(prev, next, ctx) {
    // The slot moved structurally (reconcile's UPDATE path): move Elm's live
    // rendered subtree from prev to next, preserving in-app state with no
    // re-init. @mfe/core's transplant covers the same-ref case; we only handle
    // the moved-ref case here.
    //
    // Reconcile can also call update(prev, next) where prev === next (same
    // ref, props changed, after it already transplanted). In that case the DOM
    // is already in place and clearing would wipe it, so bail out.
    if (prev === next) return;
    const app = live.get(prev);
    clearChildren(next);
    for (const child of Array.from(prev.childNodes)) {
      next.appendChild(child);
    }
    if (app) {
      live.delete(prev);
      live.set(next, app);
    }
  },
};
