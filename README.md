Demo for the Rolldown bug with commonjs interop.

Try it out:

```sh
npm ci
npm run build
npm run build-esbuild
node dist/esbuild/test.js # succeeds
node dist/rolldown/test.js # never finished
```

It looks like Rolldown has removed a chunk of a function `powMod_`:

Rolldown:

```js
function powMod_(x, y, n) {
	var k1, k2, kn, np;
	if (s7.length != n.length) s7 = dup(n);
	if ((n[0] & 1) == 0) {
		copy_(s7, x);
		copyInt_(x, 1);
		while (!equalsInt(y, 0)) {
			if (y[0] & 1) multMod_(x, s7, n);
			divInt_(y, 2);
			squareMod_(s7, n);
		}
		return;
	}
	copyInt_(s7, 0);
	for (kn = n.length; kn > 0 && !n[kn - 1]; kn--);
	np = radix - inverseModInt(modInt(n, radix), radix);
	s7[kn] = 1;
	multMod_(x, s7, n);
	if (s3.length != x.length) s3 = dup(x);
else copy_(s3, x);
	for (k1 = y.length - 1; k1 > 0 & !y[k1]; k1--);
	if (y[k1] == 0) {
		copyInt_(x, 1);
		return;
	}
	for (k2 = 1 << bpe - 1; k2 && !(y[k1] & k2); k2 >>= 1);
	for (;;) {
		mont_(x, x, n, np);
		if (k2 & y[k1]) mont_(x, s3, n, np);
	}
}
```

Esbuild:

```js
function powMod_(x, y, n) {
  var k1, k2, kn, np;
  if (s7.length != n.length) {
    s7 = dup(n);
  }
  if ((n[0] & 1) == 0) {
    copy_(s7, x);
    copyInt_(x, 1);
    while (!equalsInt(y, 0)) {
      if (y[0] & 1) {
        multMod_(x, s7, n);
      }
      divInt_(y, 2);
      squareMod_(s7, n);
    }
    return;
  }
  copyInt_(s7, 0);
  for (kn = n.length; kn > 0 && !n[kn - 1]; kn--) ;
  np = radix - inverseModInt(modInt(n, radix), radix);
  s7[kn] = 1;
  multMod_(x, s7, n);
  if (s3.length != x.length) {
    s3 = dup(x);
  } else {
    copy_(s3, x);
  }
  for (k1 = y.length - 1; k1 > 0 & !y[k1]; k1--) ;
  if (y[k1] == 0) {
    copyInt_(x, 1);
    return;
  }
  for (k2 = 1 << bpe - 1; k2 && !(y[k1] & k2); k2 >>= 1) ;
  for (; ; ) {
    if (!(k2 >>= 1)) {
      k1--;
      if (k1 < 0) {
        mont_(x, one, n, np);
        return;
      }
      k2 = 1 << bpe - 1;
    }
    mont_(x, x, n, np);
    if (k2 & y[k1]) {
      mont_(x, s3, n, np);
    }
  }
}
```

notice the part that is missing:

```js
    if (!(k2 >>= 1)) {
	k1--;
	if (k1 < 0) {
		mont_(x, one, n, np);
		return;
	}
	k2 = 1 << bpe - 1;
}
```