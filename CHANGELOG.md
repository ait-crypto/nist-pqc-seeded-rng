# Changelog

## 0.2.3 (2026-04-13)

* Bump edition to 2024 as required by `aes` and `ctr`.

## 0.2.2 (2026-04-13)

* Update `aes` to version 0.9.
* Update `ctr` to version 0.10.

## 0.2.1 (2025-04-15)

* Fix generation if destination buffer is not zeroized.

## 0.2 (2024-09-13)

* Reimplement `Seed` without `generic-array`.

## 0.1.3 (2024-09-12)

* Refactor to remove direct dependency on `generic-array`.

## 0.1.2 (2024-07-16)

* Provide convenience `TryFrom` and `From` implementation for byte slices and byte arrays.
* Add `serde` support.
* Dual license as Apache-2.0 or MIT.

## 0.1.1 (2024-07-15)

* Make the crate actually usable

## 0.1 (2024-07-15)

* Initial release.
