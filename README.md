# NIST PQC: RNG for known answer tests

This crate provides a seedable RNG that produces outputs compatible with
[`rng.c`] used by submissions to the NIST [PQC] project to obtain known answer
tests from an initial seed.

[PQC]: https://csrc.nist.gov/projects/post-quantum-cryptography/
[`rng.c`]: https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/example-files/source-code-files-for-kats.zip

## Security Notes

This crate has received no security audit. Use at your own risk.

## Minimum Supported Rust Version

This crate requires Rust 1.70 at a minimum. The MSRV may be changed in the
future, but this change will be accompanied by a minor version bump.

### License

This crate is licensed under the Apache-2.0 or MIT license.
