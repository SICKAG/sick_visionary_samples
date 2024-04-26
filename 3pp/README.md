# Third Party Code Usage

This project uses third-party code from the following sources:

## libspng

- **Repo**: https://github.com/randy408/libspng
- **Location in project**: `3pp/spng_miniz/spng/`
- **Version used**: 0.7.4
- **Files used**: `spng.h`, `spng.c`
- **License**: The BSD 2-Clause License can be found in the `LICENSE` file in the `spng/` directory.

## miniz

- **Repo**: https://github.com/richgel999/miniz
- **Location in project**: `3pp/spng_miniz/miniz/`
- **Version used**: 3.0.2
- **Files used**: `miniz.h`, `miniz.c`
- **License**: The MIT license can be found in the `LICENSE` file in the `miniz/` directory.
- **Note**: The code has been amalgamated into `miniz.h` and `miniz.c` files.

## botan

- **Repo**: https://github.com/randombit/botan
- **Location in project**: `3pp/botan/`
- **Version used**: release-2
- **Files used**: `botan_all.h`, `botan_all.cpp`
- **License**: The BSD 2-Clause License can be found in the `LICENSE` file in the `botan/` directory.
- **Note**: The code has been amalgamated for linux using these modules: aes,cbc,hmac,md5,sha2_32,sha2_64,auto_rng,system_rng
- **Note**: Intended for internal CI only
