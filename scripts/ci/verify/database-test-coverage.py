#!/usr/bin/env python3
"""Every database test runs in exactly one database suite.

A database test is a Rust test whose #[ignore] reason names DATABASE_URL, such
as `#[ignore = "requires isolated TEST_DATABASE_URL"]`; a test written by a
macro (`macro_rules! NAME { ($name:ident, ...) => { #[ignore = ...] fn $name`)
is named by the first argument of each `NAME!(` call in the same file.

Before it runs a suite, run-integration-verification.sh lists the tests that
suite's own filter selects into one file of `PACKAGE<TAB>TEST` lines, and the
suite must then pass exactly that many. This check reads those listings and
the sources, and fails when a database test is in no listing (no lane runs
it) or in more than one (two lanes run it). So no count is kept anywhere: a
lane's filter that drops a test, a new test no lane selects, and a suite that
disappears all fail here.

Usage:
  database-test-coverage.py --root ROOT --listings DIR
  database-test-coverage.py --self-test
"""

import argparse
from collections import defaultdict
from pathlib import Path
import re
import sys
import tempfile
import tomllib

IGNORE = re.compile(r'#\[ignore\s*=\s*"[^"]*DATABASE_URL[^"]*"\s*\]')
FUNCTION = re.compile(r'\bfn\s+(\$?[A-Za-z_][A-Za-z0-9_]*)')
MACRO = re.compile(r'\bmacro_rules!\s*([A-Za-z_][A-Za-z0-9_]*)')
METAVARIABLE = re.compile(r'\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([a-z]+)')


def package_of(path, root):
    """The Cargo package a source file belongs to: its nearest manifest's."""
    for directory in path.parents:
        manifest = directory / 'Cargo.toml'
        if manifest.is_file():
            data = tomllib.loads(manifest.read_text())
            if 'package' in data:
                return data['package']['name']
        if directory == root:
            break
    raise ValueError(f'{path}: no Cargo package owns this file')


def macro_tests(text, attribute, variable, where):
    """The tests a macro_rules body writes, one per call in the same file."""
    definitions = [match for match in MACRO.finditer(text) if match.start() < attribute]
    if not definitions:
        raise ValueError(f'{where}: fn ${variable} outside a macro_rules')
    definition = definitions[-1]
    matcher = METAVARIABLE.search(text, definition.end())
    if not matcher or matcher.group(1) != variable or matcher.group(2) != 'ident':
        raise ValueError(f'{where}: macro {definition.group(1)} must take the test name '
                         f'as its first argument, ${variable}:ident')
    call = re.compile(r'(?<![A-Za-z0-9_])' + re.escape(definition.group(1))
                      + r'!\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)')
    names = [match.group(1) for match in call.finditer(text)]
    if not names:
        raise ValueError(f'{where}: macro {definition.group(1)} writes database tests '
                         'but this file never calls it')
    return names


def database_tests(root):
    """(package, function name) for every database test under ROOT/crates."""
    tests = []
    for path in sorted((root / 'crates').rglob('*.rs')):
        if 'target' in path.relative_to(root).parts:
            continue
        text = path.read_text()
        for attribute in IGNORE.finditer(text):
            where = f'{path.relative_to(root)}:{text.count(chr(10), 0, attribute.start()) + 1}'
            function = FUNCTION.search(text, attribute.end())
            if not function:
                raise ValueError(f'{where}: no test function follows this #[ignore]')
            name = function.group(1)
            names = (macro_tests(text, attribute.start(), name[1:], where)
                     if name.startswith('$') else [name])
            package = package_of(path, root)
            tests.extend((package, test, where) for test in names)
    return tests


def read_listings(directory):
    """{(package, test): [suite, ...]} from the lanes' listings."""
    suites = defaultdict(list)
    files = sorted(Path(directory).glob('*.list'))
    if not files:
        raise ValueError(f'{directory}: no suite listings; no database suite ran')
    for listing in files:
        for line in listing.read_text().splitlines():
            package, separator, test = line.partition('\t')
            if not separator or not package or not test:
                raise ValueError(f'{listing}: malformed listing line {line!r}')
            suites[(package, test)].append(listing.stem)
    return suites


def check(root, directory):
    """The errors: database tests that no suite or several suites run."""
    listed = read_listings(directory)
    by_name = defaultdict(list)
    for (package, test), suites in listed.items():
        by_name[(package, test.rsplit('::', 1)[-1])].append((test, suites))
    wanted = defaultdict(list)
    for package, name, where in database_tests(root):
        wanted[(package, name)].append(where)
    errors = []
    for (package, name), places in sorted(wanted.items()):
        found = by_name.get((package, name), [])
        if len(found) < len(places):
            errors.append(f'{package} database test {name} ({", ".join(places)}) runs in no '
                          'database lane: give a lane a filter that selects it')
            continue
        if len(found) > len(places):
            errors.append(f'{package} has more tests named {name} than database tests of that '
                          f'name ({", ".join(test for test, _ in found)}); rename one')
            continue
        for test, suites in found:
            if len(suites) > 1:
                errors.append(f'{package} database test {test} runs in {len(suites)} suites '
                              f'({", ".join(sorted(suites))}); it must run in one')
    total = sum(map(len, wanted.values()))
    return errors, total, len({suite for suites in listed.values() for suite in suites})


def self_test():
    """Old fail, new pass: an unwired test, a test two suites run, a macro."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        crate = root / 'crates' / 'demo'
        (crate / 'src').mkdir(parents=True)
        (crate / 'Cargo.toml').write_text('[package]\nname = "codewire-demo"\nversion = "0.0.0"\n')
        (crate / 'src' / 'lib.rs').write_text('''
#[cfg(test)]
mod tests {
    #[tokio::test]
    #[ignore = "requires isolated TEST_DATABASE_URL"]
    async fn db_one() {}
    #[test]
    #[ignore = "requires the selected service harness"]
    fn not_a_database_test() {}
    macro_rules! case { ($name:ident, $body:block) => {
        #[test]
        #[ignore="requires DATABASE_URL"]
        fn $name() $body
    };}
    case!(db_two, {});
    case!(
        db_three,
        {}
    );
}
''')
        listings = root / 'listings'
        listings.mkdir()

        def write(**suites):
            for old in listings.iterdir():
                old.unlink()
            for suite, tests in suites.items():
                (listings / f'{suite}.list').write_text(
                    ''.join(f'codewire-demo\t{test}\n' for test in tests))
            return check(root, listings)

        assert [name for _, name, _ in database_tests(root)] == ['db_one', 'db_two', 'db_three']
        errors, total, suites = write(a=['tests::db_one', 'tests::db_two'], b=['tests::db_three'])
        assert errors == [] and total == 3 and suites == 2, errors
        # A lane whose filter drops a test (or a suite that disappears).
        errors, _, _ = write(a=['tests::db_one', 'tests::db_two'])
        assert len(errors) == 1 and 'db_three' in errors[0] and 'no database lane' in errors[0], errors
        # A new test no lane selects.
        errors, _, _ = write(a=['tests::db_two'], b=['tests::db_three'])
        assert len(errors) == 1 and 'db_one' in errors[0], errors
        # Two lanes running one test.
        errors, _, _ = write(a=['tests::db_one', 'tests::db_two'], b=['tests::db_three', 'tests::db_two'])
        assert len(errors) == 1 and 'runs in 2 suites (a, b)' in errors[0], errors
        # Listing a test that is not a database test is harmless.
        errors, _, _ = write(a=['tests::db_one', 'tests::db_two', 'tests::db_three', 'tests::other'])
        assert errors == [], errors
        # No listing at all is no proof.
        try:
            write()
        except ValueError as error:
            assert 'no suite listings' in str(error)
        else:
            raise AssertionError('an empty listing folder passed')
        # A macro that takes its name elsewhere cannot be read: fail closed.
        (crate / 'src' / 'lib.rs').write_text('''
macro_rules! case { ($body:block, $name:ident) => {
    #[ignore = "requires TEST_DATABASE_URL"]
    fn $name() $body
};}
case!({}, db_four);
''')
        try:
            database_tests(root)
        except ValueError as error:
            assert 'first argument' in str(error), error
        else:
            raise AssertionError('an unreadable test macro passed')
    print('database-test-coverage self-test: OK')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', type=Path)
    parser.add_argument('--listings', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.root or not args.listings:
        parser.error('--root and --listings are required')
    try:
        errors, total, suites = check(args.root.resolve(), args.listings)
    except ValueError as error:
        print(f'::error::{error}', file=sys.stderr)
        return 1
    for error in errors:
        print(f'::error::{error}', file=sys.stderr)
    if errors:
        return 1
    print(f'[database-test-coverage] each of {total} database tests runs in exactly one '
          f'of {suites} database suites')
    return 0


if __name__ == '__main__':
    sys.exit(main())
