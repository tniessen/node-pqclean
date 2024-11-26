# PQClean for Node.js, Deno, and more

This package provides Node.js bindings for [PQClean][], a collection of
[post-quantum cryptography][] algorithm implementations, including 16
[key encapsulation mechanisms][] and 19 [digital signature algorithms][].

In addition to the native addon for Node.js, this package also provides an
implementation for Deno and other JavaScript runtimes, such as browsers, based
on WebAssembly.

## Installation

To use this package in Node.js, install it as usual.

```sh
npm i pqclean
```

By default, node-pqclean will attempt to compile PQClean as a native addon for
Node.js. Only if that fails, for example, because necessary tools are not
installed or because the operating system is unsupported, the package will
continue with the installation, but only the WebAssembly backend will be
available at runtime.

It is possible to customize the installation procedure through the use of an npm
config variable `pqclean-backend`.

* `pqclean-backend=prefer-native` (default) attempts to build the native addon
  and only uses the WebAssembly backend if building the native addon fails.
* `pqclean-backend=native` builds and uses the native addon only. If building
  the native addon fails, the package installation fails as well.
* `pqclean-backend=wasm` does not build the native addon. Only the WebAssembly
  backend will be available at runtime. This option may be useful when loading
  native addons poses a security risk.

You can read more about npm config variables
[here](https://docs.npmjs.com/cli/v8/using-npm/config).

### Building for the web (Deno, browsers, etc.)

[Emscripten](https://emscripten.org/) and a recent version of Node.js are
required to build the web distribution, which is based on WebAssembly. If you
encounter any problems despite having installed `emcc`, please open an issue.

Clone the repository and run `npm run build-wasm && npm run build-web`. This
will produce the web distribution in `web/dist`.

## API

See [API.md](API.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

This project is distributed under the MIT license. Please check
[deps/PQClean](deps) for licenses that apply to individual algorithm
implementations.

[PQClean]: https://github.com/PQClean/PQClean
[digital signature algorithms]: https://en.wikipedia.org/wiki/Digital_signature
[key encapsulation mechanisms]: https://en.wikipedia.org/wiki/Key_encapsulation_mechanism
[post-quantum cryptography]: https://en.wikipedia.org/wiki/Post-quantum_cryptography
[nodejs/node#43630]: https://github.com/nodejs/node/issues/43630
