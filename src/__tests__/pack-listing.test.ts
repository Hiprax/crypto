/**
 * Regression tests for the `npm pack --dry-run --json` shape normaliser.
 *
 * WHY THIS FILE EXISTS. The v1.6.1 release failed in `npm publish` because npm
 * changed this output at its 12.0.0 major, from an array of package entries to
 * an object keyed by package name. `release.yml` upgrades npm to `^12`
 * immediately before publishing, and `npm publish` runs `prepublishOnly` ->
 * `npm run verify` -> `check:tarball`, so the gate ran under a different npm
 * than the standalone "Verify tarball contents" step that had passed minutes
 * earlier in the same job. It failed closed, which was correct, but it blocked
 * a release rather than catching a defect.
 *
 * The logic could not be tested before because it lived inline in a script with
 * top-level side effects. It now lives in `scripts/pack-listing.mjs`, which is
 * side-effect free, so these cases run without invoking npm at all.
 *
 * The production change each test would catch is named on the test itself.
 */
import { describe, it, expect } from '@jest/globals';
// @ts-expect-error -- plain ESM helper, no declarations; this suite is its spec.
import {
  parsePackListing,
  selectPackEntry,
} from '../../scripts/pack-listing.mjs';

/** A package entry as npm emits it, trimmed to the fields the gate reads. */
const entry = (name: string): unknown => ({
  id: `${name}@1.0.0`,
  name,
  version: '1.0.0',
  filename: 'pkg-1.0.0.tgz',
  unpackedSize: 1234,
  files: [{ path: 'package.json' }, { path: 'dist/index.js' }],
});

describe('selectPackEntry — npm output-shape normalisation', () => {
  it('reads the npm <= 11 array shape', () => {
    // Fails if the array branch is dropped, i.e. if someone "simplifies" the
    // normaliser to only understand npm 12 and breaks every npm 10/11 machine.
    const selected = selectPackEntry([entry('@hiprax/crypto')]) as {
      name: string;
      files: { path: string }[];
    };
    expect(selected).not.toBeNull();
    expect(selected.name).toBe('@hiprax/crypto');
    expect(selected.files.map(f => f.path)).toEqual([
      'package.json',
      'dist/index.js',
    ]);
  });

  it('reads the npm >= 12 object-keyed-by-package-name shape', () => {
    // This is the exact case that broke the v1.6.1 publish. Reverting the
    // normaliser to `Array.isArray(parsed) ? parsed[0] : parsed` turns it red.
    const selected = selectPackEntry({
      '@hiprax/crypto': entry('@hiprax/crypto'),
    }) as { name: string; files: { path: string }[] };
    expect(selected).not.toBeNull();
    expect(selected.name).toBe('@hiprax/crypto');
    expect(selected.files).toHaveLength(2);
  });

  it('reads a bare entry object, so a future shape without a wrapper still works', () => {
    const selected = selectPackEntry(entry('@hiprax/crypto')) as {
      name: string;
    };
    expect(selected.name).toBe('@hiprax/crypto');
  });

  it('returns null when nothing carries a files array, so the gate fails closed', () => {
    // The negative that matters: the gate must never report on a listing it
    // could not read. Each of these must yield null, NOT a truthy object.
    expect(selectPackEntry({ '@hiprax/crypto': { name: 'x' } })).toBeNull();
    expect(selectPackEntry([{ name: 'x' }])).toBeNull();
    expect(selectPackEntry([])).toBeNull();
    expect(selectPackEntry({})).toBeNull();
    expect(selectPackEntry(null)).toBeNull();
    expect(selectPackEntry(undefined)).toBeNull();
    expect(selectPackEntry('not json')).toBeNull();
    expect(selectPackEntry(42)).toBeNull();
  });

  it('rejects a files value that is not an array', () => {
    // `files: {}` or `files: null` must not be mistaken for a listing.
    expect(selectPackEntry([{ name: 'x', files: {} }])).toBeNull();
    expect(selectPackEntry({ pkg: { name: 'x', files: null } })).toBeNull();
  });

  it('skips a wrapper whose sibling entry is the one with files', () => {
    const selected = selectPackEntry({
      meta: { note: 'no files here' },
      '@hiprax/crypto': entry('@hiprax/crypto'),
    }) as { name: string };
    expect(selected.name).toBe('@hiprax/crypto');
  });
});

describe('parsePackListing — tolerating npm notice output', () => {
  it('parses a plain array payload', () => {
    expect(parsePackListing('[{"files":[]}]')).toEqual([{ files: [] }]);
  });

  it('parses a plain object payload', () => {
    expect(parsePackListing('{"pkg":{"files":[]}}')).toEqual({
      pkg: { files: [] },
    });
  });

  it('recovers when npm prints a notice line before an ARRAY payload', () => {
    expect(parsePackListing('npm notice packing\n[{"files":[]}]')).toEqual([
      { files: [] },
    ]);
  });

  it('recovers when npm prints a notice line before an OBJECT payload', () => {
    // The old implementation only searched for `[`, so an npm 12 payload behind
    // a notice line was unrecoverable. Removing the `{` search turns this red.
    expect(
      parsePackListing('npm notice packing\n{"pkg":{"files":[]}}')
    ).toEqual({ pkg: { files: [] } });
  });

  it('picks the EARLIEST structural character, not just the first bracket', () => {
    // An object payload that happens to contain a `[` later must not be sliced
    // from that bracket, which would parse a fragment or fail outright.
    const text = 'notice\n{"pkg":{"files":[{"path":"a"}]}}';
    expect(parsePackListing(text)).toEqual({
      pkg: { files: [{ path: 'a' }] },
    });
  });

  it('returns null for output with no JSON at all, so the caller fails closed', () => {
    expect(parsePackListing('npm error something went wrong')).toBeNull();
    expect(parsePackListing('')).toBeNull();
  });

  it('returns null for a truncated payload rather than a partial object', () => {
    expect(parsePackListing('[{"files":')).toBeNull();
  });
});
