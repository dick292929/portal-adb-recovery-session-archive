# Research credits and third-party notices

## The PurrTol

Part of this investigation builds on **[amemefarmer](https://github.com/amemefarmer)'s [The PurrTol](https://github.com/amemefarmer/the-purrtol)**, an earlier first generation Portal+ 15.6-inch unlock attempt. Its research notes, experiment journals, captive-portal entry approach, and kernel-stage investigation informed this work. The PurrTol-derived local server identifies its pinned upstream source URL and Git blob hash. The upstream page remains fetched from that URL rather than being copied into this repository. No root-level license file was found in that upstream repository when preparing this upload; attribution does not assign a new license to its work.

## CVE-2022-4262 proof of concept

The Chrome 106 renderer investigation uses a pinned proof of concept from **[mistymntncop/CVE-2022-4262](https://github.com/mistymntncop/CVE-2022-4262)**. The local server documents the transformations and verifies the upstream Git blob hash. The upstream exploit remains a runtime download. No root-level license file was found there when preparing this upload; no new license is assigned to the upstream source.

## Katana

The five Python files in [research/katana_src/](research/katana_src/) were downloaded from **[Daniel224455/katana](https://github.com/Daniel224455/katana)** and retain their original `SPDX-FileCopyrightText: 2026 Daniel Grobert` and `AGPL-3.0-or-later` headers. The original [AGPL license text](research/katana_src/LICENSE) has been added alongside them. These upstream files are preserved verbatim; the flattened local snapshot is explained in [TOOLS.md](TOOLS.md).

## V8 and Chromium

[v8src/](v8src/) contains partial V8 source snapshots with their original copyright headers. The [V8 BSD license](v8src/LICENSE) was retrieved from the `10.6.194` tag. Its downloaded tree index is retained as provenance; individual snapshots are not claimed to be a complete checkout of that tag.

[research/src/](research/src/) contains partial Chromium/Blink/GPU reference snapshots with their original notices. The [Chromium BSD license](research/src/LICENSE) was retrieved from the `106.0.5249.126` tag. [gl2.h](research/src/gl2.h) carries its own Khronos permission notice. [itanium_abi.html](research/src/itanium_abi.html) is a saved copy of the [Itanium C++ ABI reference](https://itanium-cxx-abi.github.io/cxx-abi/abi.html), credited to its original authors. The source folder's Chromium license does not relicense independently authored reference material.

## Firmware evidence and local work

Extracted Meta/Android configuration files in [evidence/](evidence/) retain their original content and any embedded notices. Bulk proprietary firmware and decompiled application trees are represented by an inventory rather than redistributed here.

Original investigation scripts, records, and the raw session export are archived as supplied by the repository owner. This upload does not choose a new blanket license for those files or alter third-party licensing terms.
