# Direct GitHub source files rather than submodules alone

The original PR #103 linked upstream source through pinned Git submodules.
GitHub exposes these as mode-160000 links, not ordinary tracked files.

A branch-scoped GitHub Actions job now exports the Git-tracked contents of the
three verified upstream submodules to separate readable directories:

- vendor_sources/theHarvester/
- vendor_sources/OSINT-SPY/
- vendor_sources/Mr.Holmes/

The script runs against exact pinned commits, copies content byte-for-byte,
preserves upstream LICENSE files and records SHA-256 for every copied file.
It excludes executable native binaries, symlinks, files over 5 MiB and
files matching common secret signatures. Exclusions are recorded, not hidden.

**Important:** These are source review copies only. The runtime remains governed
by src/traceatlas/integrations/thirdparty_osint.py; the 140-domain manager,
CaseDB and EvidenceStore are unchanged. Security and GPL licensing constraints
remain. No live execution parity is claimed.

The temporary import workflow uses an exact integration branch and pushes
the generated source files only there, not to main. Run full security CI after
the generated commit and remove the temporary write-enabled workflow before
merging the final code.
