# Third-party notices for Anim

Status: **HISTORICAL CORE INVENTORY RETAINED; OPTIONAL EXAMPLE PROVENANCE DOCUMENTED**

Updated: 2026-09-05. The core wheel/license inventory below was verified for
the 0.1.1 release on 2026-08-25 and is retained with its original platform scope.

This file records technical licence and artifact evidence. It is not legal
advice and does not replace the licence text shipped by each dependency.

Anim is licensed under Apache-2.0. The project licence is in `LICENSE`.

## Distribution boundary

The `anim` wheel contains Anim's own source and resources. It does not vendor or
copy the source of NumPy, jsonschema, PyYAML, rfc8785, another runtime
dependency, or an event-based model backend. Package installers obtain runtime
dependencies as separate distributions.

The public core explicitly pins nine runtime distributions, including the
transitive dependencies of its primary libraries. The CPython 3.12 graph is:

- `jsonschema==4.26.0`;
- `numpy==2.3.1`;
- `PyYAML==6.0.3`;
- `rfc8785==0.1.4`;
- `attrs==26.1.0`;
- `jsonschema-specifications==2025.9.1`;
- `referencing==0.37.0`;
- `rpds-py==2026.6.3`; and
- `typing-extensions==4.16.0`.

No named EBM backend is part of this core graph. Optional historical backend
research and its environments are not part of the Anim 0.1.1 PyPI distribution.

Anim 0.2.0 includes Anim's own optional adapter and provisioner
under `workers/pysaebm_example`; it does not bundle the upstream backend source
or its optional dependencies. The example selects public pysaebm 7.7.9 commit
`54521a9adfedf58facd7bafd741a14d9ed110d2a`, licensed under MIT. Its
[source manifest](workers/pysaebm_example/source-manifest.json) pins the exact
source files and the upstream `LICENSE` bytes, which the provisioner retains.
Optional software requirements are separate from the core graph and retain
their own distribution licences and notices. See the
[adapter runbook](docs/handoff/adapter-runbook.md) for software-only provisioning
and the synthetic evidence boundary. No upstream participant datasets are bundled
or needed by that route.

## Exact public artifact inventory

All wheel hashes below matched `uv.lock`. “Both” means the same pure-Python
wheel applies to macOS arm64 and manylinux x86_64.

| Package | Platform and exact wheel | Wheel SHA-256 | Observed licence evidence |
| --- | --- | --- | --- |
| attrs 26.1.0 | Both: `attrs-26.1.0-py3-none-any.whl` | `c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309` | MIT; `attrs-26.1.0.dist-info/licenses/LICENSE` SHA-256 `882115c95dfc2af1eeb6714f8ec6d5cbcabf667caff8729f42420da63f714e9f` |
| jsonschema 4.26.0 | Both: `jsonschema-4.26.0-py3-none-any.whl` | `d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce` | MIT; `jsonschema-4.26.0.dist-info/licenses/COPYING` SHA-256 `4f92a015a13c4d1a040bef018aa13430b4f1bc73b41b16bb846c346766de7439` |
| jsonschema-specifications 2025.9.1 | Both: `jsonschema_specifications-2025.9.1-py3-none-any.whl` | `98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe` | MIT; `jsonschema_specifications-2025.9.1.dist-info/licenses/COPYING` SHA-256 `42dcd63495f87b4eb7c7757afa379bb55a53f94afd7a5f657d9adf57236e515c` |
| numpy 2.3.1 | macOS arm64: `numpy-2.3.1-cp312-cp312-macosx_14_0_arm64.whl` | `867ef172a0976aaa1f1d1b63cf2090de8b636a7674607d514505fb7276ab08fc` | BSD-3-Clause plus bundled notices; see below |
| numpy 2.3.1 | manylinux x86_64: `numpy-2.3.1-cp312-cp312-manylinux_2_28_x86_64.whl` | `e7cbf5a5eafd8d230a3ce356d892512185230e4781a361229bd902ff403bc660` | BSD-3-Clause plus bundled notices; see below |
| PyYAML 6.0.3 | macOS arm64: `pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl` | `fc09d0aa354569bc501d4e787133afc08552722d3ab34836a80547331bb5d4a0` | MIT; `pyyaml-6.0.3.dist-info/licenses/LICENSE` SHA-256 `8d3928f9dc4490fd635707cb88eb26bd764102a7282954307d3e5167a577e8a4` |
| PyYAML 6.0.3 | manylinux x86_64: `pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` | `ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc` | MIT; same licence bytes as macOS |
| referencing 0.37.0 | Both: `referencing-0.37.0-py3-none-any.whl` | `381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231` | MIT; `referencing-0.37.0.dist-info/licenses/COPYING` SHA-256 `42dcd63495f87b4eb7c7757afa379bb55a53f94afd7a5f657d9adf57236e515c` |
| rfc8785 0.1.4 | Both: `rfc8785-0.1.4-py3-none-any.whl` | `520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48` | Apache-2.0; `rfc8785-0.1.4.dist-info/LICENSE` SHA-256 `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594` |
| rpds-py 2026.6.3 | macOS arm64: `rpds_py-2026.6.3-cp312-cp312-macosx_11_0_arm64.whl` | `538949e262e46caa31ac01bdb3c1e8f642622922cacbabbae6a8445d9dc33eaf` | MIT; `rpds_py-2026.6.3.dist-info/licenses/LICENSE` SHA-256 `314e4e91be3baa93c0fb4bccc9e4e97cd643eb839b065af921782c2175fe9909` |
| rpds-py 2026.6.3 | manylinux x86_64: `rpds_py-2026.6.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `ecabd69db66de867690f9797f2f8fa27ba501bbc24540cbdbdc649cd15888ba6` | MIT; same licence bytes as macOS |
| typing-extensions 4.16.0 | Both: `typing_extensions-4.16.0-py3-none-any.whl` | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` | PSF-2.0; `typing_extensions-4.16.0.dist-info/licenses/LICENSE` SHA-256 `3b2f81fe21d181c499c59a256c8e1968455d6689d269aa85373bfb6af41da3bf` |

## NumPy bundled notices

The macOS and Linux NumPy wheels contain the following additional notice files:

| Path | SHA-256 | Licence |
| --- | --- | --- |
| `numpy/ma/LICENSE` | `05f3b88351988ecfad10abe92c0c50e5875c6452d5009a0084cc291551ffcca6` | BSD-3-Clause |
| `numpy/_core/include/numpy/random/LICENSE.txt` | `fbc539f47d0cf83bc61378080fb873d5c14630126cacbfe754035c3926daa5ec` | Zlib |
| `numpy/random/LICENSE.md` | `103166b62b80443afb9eb3488e052ea06be0cff566b908f199e561fde49af19f` | NCSA OR BSD-3-Clause |

The platform-specific top-level NumPy notice hashes are:

- macOS `numpy-2.3.1.dist-info/LICENSE.txt`:
  `d84715000c6b3fd8719b2027238b6f6457cb853b2eb7023821a585949387f7bf`;
- Linux `numpy-2.3.1.dist-info/LICENSE.txt`:
  `2046a3130e50b11c01659b3a0d963e6ae0b7436ff8e89cbcfd9e87bc6112d595`.

## Technical compatibility finding

The exact core graph above contains permissive or PSF-style licences. The
technical audit found no GPL, AGPL, or other reciprocal-copyleft component in
the nine runtime artifacts. An Apache-2.0 project licence is technically
compatible with the observed graph, subject to retaining required third-party
notices. The project owner selected Apache-2.0 on 2026-08-25.

The audit covers CPython 3.12 on macOS arm64 and manylinux x86_64. musl Linux,
other architectures, optional backends, development tools, and build tools are
outside this runtime notice.
