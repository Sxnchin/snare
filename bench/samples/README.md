# Samples

`juice-shop-sample.har` is a small hand-written HAR 1.2 file for trying
`snare corpus import-har`. Every value in it is fake (the JWT is not signed
by anything real). It contains six entries on purpose:

- four on `shop.lab.test` that should be imported (a search, a login with a
  password and a JWT, a base64-encoded image, a product fetch with a bearer
  token);
- one on a third-party host, skipped by `-host shop.lab.test`;
- one with status 0 (an aborted request), always skipped.

```sh
snare corpus import-har -route juice-shop -host shop.lab.test bench/samples/juice-shop-sample.har
```
