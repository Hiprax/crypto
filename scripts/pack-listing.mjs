/**
 * Normalisation of `npm pack --dry-run --json` output, extracted so it can be
 * unit-tested without running npm.
 *
 * **npm changed this output shape at the 12.0.0 major**, and the change is
 * silent: both forms are valid JSON carrying the same data, so a parser written
 * against one simply finds no `files` array in the other.
 *
 *   npm <= 11:  [ { id, name, version, files: [...], ... } ]        // array
 *   npm >= 12:  { "<pkg name>": { id, name, version, files: [...] } } // keyed object
 *
 * This bit the 1.6.1 release: `release.yml` upgrades npm to `^12` immediately
 * before `npm publish`, `npm publish` runs `prepublishOnly` (`npm run verify`),
 * and `verify` ends with `check:tarball`. The standalone "Verify tarball
 * contents" step had already passed minutes earlier under the runner's npm 10,
 * so the gate was green and red in the same job, against the same tree, purely
 * because of the npm version in scope. The gate failed CLOSED, which is the
 * correct direction, but it blocked a publish rather than catching a real
 * defect.
 *
 * Both shapes are accepted deliberately. Pinning only the new one would break
 * every contributor still on npm 10/11 running `npm run verify` locally, and
 * pinning only the old one is what just failed.
 */

/**
 * Reduce whatever `npm pack --json` printed to the single package entry that
 * carries a `files` array, or `null` when there is no such entry.
 *
 * Returning `null` rather than throwing keeps the caller's fail-closed branch in
 * one place: the gate refuses to report on a tarball it could not inspect.
 *
 * @param {unknown} parsed - the already-JSON-parsed stdout
 * @returns {{files: Array<{path: string}>} | null}
 */
export function selectPackEntry(parsed) {
  if (!parsed || typeof parsed !== 'object') return null;

  // npm <= 11: an array of package entries. `npm pack` can be asked for several
  // packages at once, but this gate always packs exactly one, so entry 0 is it.
  const candidates = Array.isArray(parsed)
    ? parsed
    : // npm >= 12: an object keyed by package name. Take the values. The bare
      // entry itself is also accepted, so a future shape that drops the wrapper
      // keeps working.
      [parsed, ...Object.values(parsed)];

  for (const candidate of candidates) {
    if (candidate && Array.isArray(candidate.files)) return candidate;
  }
  return null;
}

/**
 * Parse `npm pack --dry-run --json` stdout, tolerating a stray leading notice
 * line that npm has historically printed before the JSON on some versions.
 *
 * @param {string} text - raw stdout
 * @returns {unknown} the parsed value, or `null` if nothing parsed
 */
export function parsePackListing(text) {
  const attempt = value => {
    try {
      return JSON.parse(value);
    } catch {
      return undefined;
    }
  };

  const direct = attempt(text);
  if (direct !== undefined) return direct;

  // Retry from the first structural character, so a leading human-readable
  // line does not defeat the parse. `{` covers npm >= 12, `[` covers earlier.
  const starts = [text.indexOf('['), text.indexOf('{')].filter(i => i !== -1);
  if (starts.length === 0) return null;
  const sliced = attempt(text.slice(Math.min(...starts)));
  return sliced === undefined ? null : sliced;
}
