# NIST PQC: RNG for known answer tests

This crate provides a seedable RNG that produces outputs compatible with
[`rng.c`] used by submissions to the NIST [PQC] project to obtain known answer
tests from an initial seed.

[PQC]: https://csrc.nist.gov/projects/post-quantum-cryptography/
[`rng.c`]: https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/example-files/source-code-files-for-kats.zip
