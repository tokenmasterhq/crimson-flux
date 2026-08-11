# CrimsonFlux third-party notices

This file records the third-party software that is material to CrimsonFlux's
request-signing path. CrimsonFlux's original source code is licensed under the
Apache License, Version 2.0, in the repository root `LICENSE` file.

Copyright 2026 CrimsonFlux contributors.

## Source provenance and non-clean-room statement

CrimsonFlux contains a project-owned, narrow HTTP adapter for QR login,
keyword search, public user-note enumeration, and note detail retrieval. The
adapter uses documented/public Python APIs from `xhshow` for local request
signing. No source file from Spider_XHS is required, vendored, copied as a
subtree, or imported as a runtime dependency by the current release design.

Earlier contributors reviewed Spider_XHS while evaluating the first
architecture. Therefore CrimsonFlux does **not** claim that its implementation
was produced under a strict legal clean-room process. The accurate, limited
claim is that a compliant release must not distribute or depend on Spider_XHS
source code. A strict clean-room claim would require separated specification
and implementation teams plus independent records; this project does not have
that evidence.

Deleting a directory from the latest checkout is insufficient if old source
objects remain reachable in Git history. The first public release must be made
from an audited new history and must scan all Git objects, the Source ZIP,
package artifacts, Docker context, and image layers. See
`docs/RELEASE_GATES.md`.

## xhshow 0.2.0

- Project: [Cloxl/xhshow](https://github.com/Cloxl/xhshow)
- PyPI: [xhshow 0.2.0](https://pypi.org/project/xhshow/0.2.0/)
- Relationship: direct, pinned runtime dependency installed from PyPI; its
  source is not copied into this repository
- Licensed release tag: `v0.2.0`
- Tag commit: `5f45309a06b2bb94131ccb51f158b0f2b2ff873a`
- Wheel SHA-256:
  `4de6f632ff911621b55335f7772187dcd4eed414142057120a37bfd46ca6d4bb`
- Source distribution SHA-256:
  `1ae45ce889d0041d57b6eff5dbcbcc31a06f3df351c80b4a50bac983a0e1fe44`
- License: MIT

The following text is reproduced from the `LICENSE` file at the pinned tag:

```text
MIT License

Copyright (c) 2024 Cloxl

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## PyCryptodome 3.23.0

- Project: [Legrandin/pycryptodome](https://github.com/Legrandin/pycryptodome)
- Release: [v3.23.0](https://github.com/Legrandin/pycryptodome/tree/v3.23.0)
- Relationship: transitive runtime dependency required by `xhshow`; resolved
  and hash-locked by `uv.lock` and `requirements.lock`
- Source distribution SHA-256:
  `447700a657182d60338bab09fdb27518f8856aecd80ae4c6bdddb67ff5da44ef`
- Platform wheel SHA-256 values: recorded exhaustively in `uv.lock` and
  `requirements.lock`
- License: code originating from PyCrypto is dedicated to the public domain;
  direct PyCryptodome contributions use the BSD 2-Clause license

The following terms are reproduced from PyCryptodome's `LICENSE.rst` at
`v3.23.0`:

### Public-domain portion

All code originating from PyCrypto is free and unencumbered software released
into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### BSD 2-Clause portion

All direct contributions to PyCryptodome are released under the following
license. The copyright of each piece belongs to the respective author.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Other dependencies

All other Python packages, container base layers, and system libraries remain
governed by their own licenses. Release CI must generate a dependency
inventory from `uv.lock`/`requirements.lock` and an SPDX SBOM from the final
reference container. An inventory or SBOM does not replace required license
texts, attribution, source-offer obligations, or human review. Every
`NOASSERTION` entry must be resolved before public release.
