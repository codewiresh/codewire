// Which design-fixture tests check the page at the mobile project's width.
// A test does when it reads the viewport, isMobile, touch or the page's
// geometry, directly or through a helper function of its file, before it sets
// a viewport of its own (setViewportSize, or a context with one). Those tests
// carry the @mobile tag (designFixtureMobileTag) and run in both fixture
// projects; the rest run in the desktop project only.

const reads = /viewportSize\(\)|isMobile|project\.name|hasTouch|boundingBox|getBoundingClientRect|toBeInViewport|scrollWidth|clientWidth|innerWidth|innerHeight/;
const ownViewport = /setViewportSize|newContext\(/;
// The start of a top-level helper, a hook or describe, or a test; a test's
// title follows `test(` as a string literal.
const blockStart = /^(?:async function (\w+)|function (\w+)|const (\w+) = (?:async )?\(|test\.(?:describe|use|beforeEach|afterEach|beforeAll|afterAll)\(|\s*test(?:\.only|\.fixme)?\(\s*("[^"\n]*"|`[^`\n]*`|'[^'\n]*'))/gm;

export type FixtureTest = { title: string; mobile: boolean; tagged: boolean };

const firstIndex = (text: string, pattern: RegExp) => {
  const match = pattern.exec(text);
  return match ? match.index : -1;
};

export function classifyFixtureTests(source: string, tag: string): FixtureTest[] {
  const starts = [...source.matchAll(blockStart)];
  const blocks = starts.map((match, index) => ({
    match,
    text: source.slice(match.index, index + 1 < starts.length ? starts[index + 1].index : source.length),
  }));
  const helpers = new Map<string, string>();
  for (const { match, text } of blocks) {
    const name = match[1] ?? match[2] ?? match[3];
    if (name) helpers.set(name, text);
  }
  const calls = (text: string, name: string) => new RegExp(`\\b${name}\\(`).test(text);
  // Helpers that read the page, directly or through another such helper.
  const readers = new Set([...helpers].filter(([, text]) => reads.test(text)).map(([name]) => name));
  for (let grew = true; grew;) {
    grew = false;
    for (const [name, text] of helpers) {
      if (!readers.has(name) && [...readers].some((reader) => calls(text, reader))) {
        readers.add(name);
        grew = true;
      }
    }
  }
  // A hook that reads the page reads it for every test of its file.
  const hookReads = blocks.some(({ match, text }) => /^test\.(?:beforeEach|beforeAll)\(/.test(match[0]) && reads.test(text));
  const readIndex = (text: string) => {
    const indexes = [firstIndex(text, reads),
      ...[...readers].map((name) => firstIndex(text, new RegExp(`\\b${name}\\(`)))].filter((index) => index >= 0);
    return indexes.length ? Math.min(...indexes) : -1;
  };
  return blocks.filter(({ match }) => match[4] !== undefined).map(({ match, text }) => {
    const read = readIndex(text);
    const own = firstIndex(text, ownViewport);
    const header = text.slice(0, text.search(/=>|async\s*\(/));
    return {
      title: match[4].slice(1, -1),
      mobile: hookReads || (read >= 0 && (own < 0 || read < own)),
      tagged: header.includes(`"${tag}"`),
    };
  });
}
