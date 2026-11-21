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

A pull request's tests are compiled from its head merged onto main (#5146),
but its lanes are the head's own. With --compiled-root MERGED, ROOT is the
head and only the database tests both trees define are checked, counted as
MERGED defines them. A test main renamed or removed since the head's base is
in no compiled binary, and one main added may be in no head lane; main's own
run checks both. The pull request's own tests are in both trees, so a test
it adds or renames is still checked. The tests left out are reported by name,
and a MERGED that is missing or holds no database test fails rather than
narrowing nothing.

Usage:
  database-test-coverage.py --root ROOT [--compiled-root MERGED] --listings DIR
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
# How many skipped tests the report names before it only counts them.
SHOWN = 20
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


def check(root, directory, compiled_root=None):
    """The errors: database tests that no suite or several suites run."""
    listed = read_listings(directory)
    by_name = defaultdict(list)
    for (package, test), suites in listed.items():
        by_name[(package, test.rsplit('::', 1)[-1])].append((test, suites))
    tests = database_tests(root)
    skipped = {}
    if compiled_root is not None:
        if not compiled_root.is_dir():
            raise ValueError(f'{compiled_root}: the merged source is not a folder')
        compiled = database_tests(compiled_root)
        if not compiled:
            raise ValueError(f'{compiled_root}: the merged source defines no database test')
        in_root = {(package, name) for package, name, _ in tests}
        in_compiled = {(package, name) for package, name, _ in compiled}
        skipped = {'renamed or removed on main': sorted(in_root - in_compiled),
                   'added on main': sorted(in_compiled - in_root)}
        tests = [test for test in compiled if test[:2] in in_root]
    wanted = defaultdict(list)
    for package, name, where in tests:
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
    return errors, total, len({suite for suites in listed.values() for suite in suites}), skipped


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
        errors, total, suites, _ = write(a=['tests::db_one', 'tests::db_two'], b=['tests::db_three'])
        assert errors == [] and total == 3 and suites == 2, errors
        # A lane whose filter drops a test (or a suite that disappears).
        errors, _, _, _ = write(a=['tests::db_one', 'tests::db_two'])
        assert len(errors) == 1 and 'db_three' in errors[0] and 'no database lane' in errors[0], errors
        # A new test no lane selects.
        errors, _, _, _ = write(a=['tests::db_two'], b=['tests::db_three'])
        assert len(errors) == 1 and 'db_one' in errors[0], errors
        # Two lanes running one test.
        errors, _, _, _ = write(a=['tests::db_one', 'tests::db_two'], b=['tests::db_three', 'tests::db_two'])
        assert len(errors) == 1 and 'runs in 2 suites (a, b)' in errors[0], errors
        # Listing a test that is not a database test is harmless.
        errors, _, _, _ = write(a=['tests::db_one', 'tests::db_two', 'tests::db_three', 'tests::other'])
        assert errors == [], errors
        # No listing at all is no proof.
        try:
            write()
        except ValueError as error:
            assert 'no suite listings' in str(error)
        else:
            raise AssertionError('an empty listing folder passed')
        # A pull request built merged onto main: main renamed db_one to
        # db_renamed and added db_main, which the head's lanes don't run.
        merged = root / 'merged'
        (merged / 'crates' / 'demo' / 'src').mkdir(parents=True)
        (merged / 'crates' / 'demo' / 'Cargo.toml').write_text((crate / 'Cargo.toml').read_text())
        (merged / 'crates' / 'demo' / 'src' / 'lib.rs').write_text(
            (crate / 'src' / 'lib.rs').read_text().replace('fn db_one()', 'fn db_renamed()')
            + '#[ignore = "requires TEST_DATABASE_URL"]\nfn db_main() {}\n')
        compiled = ['tests::db_renamed', 'tests::db_two', 'tests::db_three']
        write(a=compiled)
        # Scanning the head alone wants db_one, which no compiled binary has.
        errors, _, _, _ = check(root, listings)
        assert len(errors) == 1 and 'db_one' in errors[0], errors
        # Scanning the merged tree alone wants main's db_renamed and db_main.
        write(a=['tests::db_two', 'tests::db_three'])
        errors, _, _, _ = check(merged, listings)
        assert len(errors) == 2 and 'db_main' in errors[0] and 'db_renamed' in errors[1], errors
        # Both trees: only db_two and db_three are wanted, and they run.
        errors, total, _, skipped = check(root, listings, merged)
        assert errors == [] and total == 2, errors
        assert skipped == {'renamed or removed on main': [('codewire-demo', 'db_one')],
                           'added on main': [('codewire-demo', 'db_main'), ('codewire-demo', 'db_renamed')]}, skipped
        # The head's own test still counts: a lane that drops db_three fails.
        write(a=['tests::db_two'])
        errors, _, _, _ = check(root, listings, merged)
        assert len(errors) == 1 and 'db_three' in errors[0], errors
        # The pull request renames its own db_two to db_pr, in both trees, and
        # its lanes still list the old name: db_pr is wanted and runs nowhere.
        for tree in (crate, merged / 'crates' / 'demo'):
            source = tree / 'src' / 'lib.rs'
            source.write_text(source.read_text().replace('case!(db_two,', 'case!(db_pr,'))
        write(a=['tests::db_two', 'tests::db_three'])
        errors, _, _, _ = check(root, listings, merged)
        assert len(errors) == 1 and 'db_pr' in errors[0] and 'no database lane' in errors[0], errors
        # A merged source that is missing, or holds no database test, fails
        # closed instead of checking nothing.
        empty = root / 'merged-empty'
        (empty / 'crates').mkdir(parents=True)
        for bad, words in ((root / 'merged-missing', 'not a folder'), (empty, 'no database test')):
            try:
                check(root, listings, bad)
            except ValueError as error:
                assert words in str(error), error
            else:
                raise AssertionError(f'{bad.name} passed')
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
    parser.add_argument('--compiled-root', type=Path)
    parser.add_argument('--listings', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.root or not args.listings:
        parser.error('--root and --listings are required')
    try:
        errors, total, suites, skipped = check(
            args.root.resolve(), args.listings,
            args.compiled_root.resolve() if args.compiled_root else None)
    except (ValueError, OSError) as error:
        print(f'::error::{error}', file=sys.stderr)
        return 1
    for error in errors:
        print(f'::error::{error}', file=sys.stderr)
    if errors:
        return 1
    for why, tests in skipped.items():
        if tests:
            shown = ', '.join(f'{package}::{name}' for package, name in tests[:SHOWN])
            more = f' and {len(tests) - SHOWN} more' if len(tests) > SHOWN else ''
            print(f'[database-test-coverage] not checked here, {len(tests)} defined by one tree '
                  f'only ({why}; main\'s run checks them): {shown}{more}')
    print(f'[database-test-coverage] each of {total} database tests runs in exactly one '
          f'of {suites} database suites')
    return 0


if __name__ == '__main__':
    sys.exit(main())
