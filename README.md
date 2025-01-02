Demo for the Rolldown bug with commonjs interop.

Try it out:

```sh
npm ci
npm run build
node dist/start.js
```

The issue is that `__export` is pulled into a separate file since it is reused from multiples
files (`end.js` uses it for commonjs interop) but is referenced by `start.js` as if it in scope.
