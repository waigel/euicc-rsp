# Test material

## `profile.der`

A complete, valid profile package, used as the Unprotected Profile Package
(UPP) input to the Bound Profile Package tests (`tests/test_bpp.c`). Test
material only -- it is not tied to any real operator or subscriber.

Provenance: built from `euicc-tools`' own example profile source with
`euicc-tools`' `euicc build` command, run from this repository's root:

```sh
euicc build ~/git/waigel/euicc-tools/editors/vscode/examples/profile.vn \
      -o testdata/profile.der
```

That source (`editors/vscode/examples/profile.vn`) is the package
`euicc check -s` accepts without a single finding, chosen deliberately so a
failure in the BPP round trip is about the binding, never about the
profile. At the time this file was produced, that command reported "8
profile elements written", and:

```sh
euicc check testdata/profile.der
```

reported "0 errors, 0 warnings, 114 rule instances fired over 8 profile
elements" -- a clean package, 736 bytes.

Regenerate it the same way if `editors/vscode/examples/profile.vn` ever
changes; the exact bytes are not meaningful on their own, only that they
decode and check clean.

See `testdata/sgp26/README.md` for the DP certificate and key material
used elsewhere in this project's tests.
