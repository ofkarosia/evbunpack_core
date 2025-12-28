# evbunpack_core
A Rust library that supports reading contents and restoring PE from executables packaged by Enigma Virtual Box

This project is still in development. Currently it is not ready to be published on public registry.

## Features
- Auto detection for:
  - VFS type: Modern, Legacy
  - PE variant: 10.70, 9.70, 7.80
- Optional decompression support

## Limitations
- Does not support multiple root folders
- For root folders, only `%DEFAULT FOLDER%` is supported

## Acknowledgements
This project is based on the logic and research of [the original Python implementation](https://github.com/mos9527/evbunpack).
Thanks to the original authors for their groundwork on the EVB format.

## License
[Apache 2.0](./LICENSE)
