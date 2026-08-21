// shell/shell.js — @mfe/framework thin-shell entry.
//
// Boots the fxstore docs app (route '/' -> template 'fxstore') and mounts the
// Elm docs MFE into the [data-mfe="fxstore-page"] slot of that template. The
// route table mirrors the main site exactly: '/' is the fixpoint-linux landing
// and '/fxstore' is this fxstore page. Matching the main site means a
// data-mfe-route like '/fxstore' or '/' resolves the same way on either page,
// so cross-site MFE nav links agree on the target route.
//
// The page ships statically pre-rendered (see scripts/ssg.mjs): the #app root
// carries an `ssr` attribute, so createApp rehydrates the existing DOM in
// place instead of wiping it and re-fetching the template on first paint.

import { createApp } from '@mfe/framework';

const app = await createApp({
  root: document.getElementById('app'),
  routes: [
    { path: '/', template: 'fixpoint', name: 'home' },
    { path: '/fxstore', template: 'fxstore', name: 'fxstore' },
  ],
  basePath: '/',
  // fxstore's templates are served from /fxstore/shell/templates (the main
  // site owns /shell/templates). Pin the baseURL here so both route templates
  // resolve under this site's shell regardless of the deep-link subpath.
  baseURL: '/fxstore/shell/templates',
  // The SSG output only pre-renders the fxstore home route. Rehydrate only
  // when the current pathname matches that pre-rendered route (i.e. the
  // fxstore page); any other path (including the landing) needs a fresh
  // client render.
  ssr: (window.location.pathname.replace(/\/+$/, '') || '/') === '/fxstore',
});

// Expose the app handle so the shell/host can inspect or drive it later.
window.__fxstoreApp = app;
