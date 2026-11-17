import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from mutants_gate import (
    GateError, active_mutant, classify, hunk_ownership, parse_changes, parse_listing, partition,
    read_results, selected_or_fail, scope_for, test_module_line, verdict,
)

CONFIG = {'irrelevant': ['*.md', 'LICENSE'], 'scope': ['src/main.rs']}


class SelectionTests(unittest.TestCase):
    def test_source_test_hunks_do_not_select_the_whole_production_file(self):
        self.assertEqual(hunk_ownership('@@ -120 +120 @@\n-old\n+new\n', 100, 100), (False, True))
        self.assertEqual(hunk_ownership('@@ -20 +20 @@\n-old\n+new\n', 100, 100), (True, False))
        self.assertEqual(hunk_ownership('@@ -20 +20 @@\n-old\n+new\n@@ -120 +120 @@\n-old\n+new\n', 100, 100), (True, True))
        self.assertEqual(hunk_ownership('@@ -99,0 +100 @@\n+new\n', 100, 100), (False, True))

    def test_test_helpers_before_production_do_not_hide_production_changes(self):
        source = '#[cfg(test)]\nconst HELPER: u8 = 1;\nfn production() {}\n#[cfg(test)]\nmod tests {\n}\n'
        boundary = test_module_line(source)
        self.assertEqual(boundary, 4)
        self.assertEqual(hunk_ownership('@@ -3 +3 @@\n-old\n+new\n', boundary, boundary), (True, False))

    def test_test_deletion_and_production_union(self):
        changes = parse_changes('D\0tests/cli.rs\0M\0src/main.rs\0')
        kinds = {classify(p, s, CONFIG) for p, s in changes.items()}
        self.assertEqual(kinds, {'tests', 'production'})
        self.assertEqual(scope_for({p: classify(p, s, CONFIG) for p, s in changes.items()}, CONFIG), {'src/main.rs'})

    def test_classes(self):
        for path, status, expected in [
            ('README.md', 'M', 'irrelevant'), ('Cargo.lock', 'M', 'build configuration'),
            ('.cargo/mutants.toml', 'M', 'gate'), ('src/main.rs', 'D', 'deleted production'),
            ('src/secure_enclave.swift', 'M', 'unsupported production'),
            ('fixtures/data.json', 'A', 'fixtures'), ('other', 'M', 'unclassified'),
        ]:
            with self.subTest(path=path):
                self.assertEqual(classify(path, status, CONFIG), expected)

    def test_irrelevant_does_not_select_scope(self):
        self.assertEqual(scope_for({'README.md': classify('README.md', 'M', CONFIG)}, CONFIG), set())

    def test_deleted_production_selects_critical_scope(self):
        self.assertEqual(scope_for({'src/old.rs': 'deleted production'}, CONFIG), {'src/main.rs'})

    def test_unknown_path_fails_closed(self):
        with self.assertRaisesRegex(GateError, 'unclassified paths: unknown'):
            scope_for({'unknown': 'unclassified'}, CONFIG)
        with self.assertRaisesRegex(GateError, 'unclassified paths: src/secure_enclave.swift'):
            scope_for({'src/secure_enclave.swift': 'unsupported production'}, CONFIG)
        with self.assertRaisesRegex(GateError, 'empty configured critical scope'):
            scope_for({'tests/guard.rs': 'tests'}, {'scope': []})

    def test_partitions_cover_union_exactly_and_fail_overflow(self):
        names = ['critical-a', 'critical-b', 'changed-c', 'changed-d', 'both']
        parts = [partition(names, 3, index, 2) for index in range(3)]
        self.assertEqual(sorted(name for part in parts for name in part), sorted(names))
        with self.assertRaisesRegex(GateError, 'capacity exceeded'):
            partition(names, 2, 0, 2)
        with self.assertRaisesRegex(GateError, 'invalid shard'):
            partition(names, 3, 3, 2)

    def test_platform_cfg_routes_function_and_rejects_unknown_forms(self):
        source = '#[cfg(target_os = "macos")]\nfn darwin() {}\n#[cfg(test)]\nmod tests {\n}\n'
        item = {'file': 'src/main.rs', 'span': {'start': {'line': 2}},
                'function': {'span': {'start': {'line': 2}}}}
        self.assertTrue(active_mutant(item, 'macos', source))
        self.assertFalse(active_mutant(item, 'linux', source))
        item['function']['span']['start']['line'] = 1
        self.assertTrue(active_mutant(item, 'macos', source))
        self.assertFalse(active_mutant(item, 'linux', source))
        with self.assertRaisesRegex(GateError, 'unsupported cfg'):
            active_mutant(item, 'macos', source.replace('target_os = "macos"', 'feature = "new"'))

    def test_non_function_constant_mutations_still_route_platform_cfg(self):
        source = '#[cfg(target_os = "linux")]\npub(crate) const LIMIT: usize = 16 * 1024;\n'
        item = {'name': 'limit', 'file': 'src/store.rs', 'span': {'start': {'line': 2}}, 'function': None}
        self.assertTrue(active_mutant(item, 'linux', source))
        self.assertFalse(active_mutant(item, 'macos', source))
        with self.assertRaisesRegex(GateError, 'unsupported non-function'):
            active_mutant(item, 'macos', source.replace('pub(crate) const LIMIT: usize = 16 * 1024;', 'unknown();'))

    def test_rename(self):
        self.assertEqual(parse_changes('R100\0src/old.rs\0src/new.rs\0'),
                         {'src/old.rs': 'D', 'src/new.rs': 'A'})

    def test_listing(self):
        self.assertEqual(parse_listing(''), [])
        self.assertEqual(parse_listing('[]'), [])
        self.assertEqual(parse_listing('[{"name": "a"}, {"name": "b"}]'), ['a', 'b'])
        for text in ('{', '[{"file": "a"}]', '[{"name": "a"}, {"name": "a"}]'):
            with self.subTest(text=text), self.assertRaisesRegex(GateError, 'selection error'):
                parse_listing(text)

    def test_empty_relevant_selection(self):
        with self.assertRaisesRegex(GateError, 'empty selection'):
            selected_or_fail(True, [])
        selected_or_fail(False, [])


class ResultsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'outcomes.json'

    def write(self, summary='CaughtMutant', count=1):
        kinds = {'CaughtMutant': 'caught', 'MissedMutant': 'missed', 'Timeout': 'timeout', 'Unviable': 'unviable'}
        data = {'outcomes': [{'scenario': 'Baseline', 'summary': 'Success', 'log_path': 'baseline.log'},
                {'scenario': {'Mutant': {'name': 'mutant'}}, 'summary': summary, 'log_path': 'mutant.log'}],
                'total_mutants': count, 'caught': 0, 'missed': 0, 'timeout': 0, 'unviable': 0}
        data[kinds[summary]] = 1
        self.path.write_text(json.dumps(data))
        (self.path.parent / 'baseline.log').write_text('baseline passed')
        (self.path.parent / 'mutant.log').write_text('product assertion failed')

    def test_missing_baseline_fails(self):
        self.write()
        data = json.loads(self.path.read_text())
        data['outcomes'].pop(0)
        self.path.write_text(json.dumps(data))
        with self.assertRaisesRegex(GateError, 'missing or duplicate baseline'):
            read_results(self.path, ['mutant'])

    def test_infrastructure_failure_is_not_a_catch(self):
        self.write()
        for message in ('VAULT_HARNESS_ERROR: accept fixture compilation failed',
                        'thread panicked\nfixture compile', 'thread panicked\ncompile fault library'):
            (self.path.parent / 'mutant.log').write_text(message)
            with self.subTest(message=message), self.assertRaisesRegex(GateError, 'harness error invalidates mutant'):
                read_results(self.path, ['mutant'])

    def test_missing_log_is_not_a_catch(self):
        self.write()
        (self.path.parent / 'mutant.log').unlink()
        with self.assertRaisesRegex(GateError, 'incomplete'):
            read_results(self.path, ['mutant'])

    def test_missing_and_malformed(self):
        with self.assertRaisesRegex(GateError, 'incomplete'):
            read_results(self.path, ['mutant'])
        self.path.write_text('{')
        with self.assertRaisesRegex(GateError, 'incomplete'):
            read_results(self.path, ['mutant'])

    def test_count_and_identity_mismatch(self):
        self.write(count=2)
        with self.assertRaisesRegex(GateError, 'incomplete'):
            read_results(self.path, ['mutant'])
        self.write()
        with self.assertRaisesRegex(GateError, 'incomplete'):
            read_results(self.path, ['other'])

    def test_missed_timeout_and_confirmed_hang(self):
        for summary, message in [('MissedMutant', 'missed'), ('Timeout', 'unresolved timeout')]:
            self.write(summary)
            with self.assertRaisesRegex(GateError, message):
                verdict(read_results(self.path, ['mutant']))
        verdict({'mutant': 'confirmed hang'})
        self.write()
        verdict(read_results(self.path, ['mutant']))


class MixedChangeFixture(unittest.TestCase):
    def test_deleted_test_and_covered_change_select_union_and_fail_on_critical_miss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('scripts', '.cargo', 'src', 'tests', 'bin'):
                (root / directory).mkdir()
            shutil.copy(Path(__file__).with_name('mutants_gate.py'), root / 'scripts/mutants_gate.py')
            (root / '.cargo/mutants-gate.toml').write_text(
                'scope = ["src/store.rs"]\nirrelevant = ["*.md"]\nbudget_seconds = 60\n'
                'timeout_seconds = 10\nbuild_timeout_seconds = 10\njobs = 1\nshards = 1\nmax_per_shard = 5\n'
                '[[linux_critical]]\nfile = "src/store.rs"\nfunction = "critical"\n')
            (root / 'src/main.rs').write_text('fn value() -> i32 { 1 }\n')
            (root / 'src/store.rs').write_text('fn critical() -> bool { false }\n')
            (root / 'tests/guard.rs').write_text('// critical oracle\n')
            (root / '.gitignore').write_text('/bin/\n/.work/\n')
            subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=fixture', '-c',
                            'user.email=fixture@example.invalid', 'commit', '-qm', 'base'],
                           check=True, capture_output=True)
            (root / 'tests/guard.rs').unlink()
            (root / 'src/main.rs').write_text('fn value() -> i32 { 2 }\n')
            rustc = root / 'bin/rustc'
            rustc.write_text('#!/bin/sh\nprintf "host: x86_64-unknown-linux-gnu\\n"\n')
            rustc.chmod(0o755)
            cargo = root / 'bin/cargo'
            cargo.write_text('#!' + sys.executable + '\n' + r'''
import json, os, pathlib, re, sys, time
args = sys.argv[1:]
if os.environ.get('FAKE_MUTANT_WAIT') and '--list' in args:
    time.sleep(3)
def mutant(file, name):
    return {'name': name, 'file': file, 'span': {'start': {'line': 1}},
            'function': {'span': {'start': {'line': 1}}}}
critical = mutant('src/store.rs', 'src/store.rs:1:1: critical mutation')
changed = mutant('src/main.rs', 'src/main.rs:1:1: changed mutation')
items = [critical, changed]
if '--version' in args:
    print('cargo-mutants fixture')
elif '--list' in args:
    if '-f' in args:
        items = [x for x in items if x['file'] == args[args.index('-f') + 1]]
    if '--in-diff' in args:
        items = [changed]
    if '--re' in args:
        items = [x for x in items if re.search(args[args.index('--re') + 1], x['name'])]
    print(json.dumps(items))
else:
    out = pathlib.Path(args[args.index('--output') + 1]) / 'mutants.out'
    (out / 'log').mkdir(parents=True)
    (out / 'log/baseline.log').write_text('baseline passed')
    outcomes = [{'scenario': 'Baseline', 'summary': 'Success', 'log_path': 'log/baseline.log'}]
    partial = bool(os.environ.get('FAKE_PARTIAL'))
    if partial:
        items = [changed]
    for item in items:
        kind = 'MissedMutant' if item == critical else 'CaughtMutant'
        log = 'log/' + ('critical' if item == critical else 'changed') + '.log'
        (out / log).write_text('oracle passed' if item == critical else 'behavior assertion failed')
        outcomes.append({'scenario': {'Mutant': item}, 'summary': kind, 'log_path': log})
    (out / 'outcomes.json').write_text(json.dumps({'outcomes': outcomes, 'total_mutants': len(items),
        'caught': 1, 'missed': int(not partial), 'timeout': 0, 'unviable': 0}))
    if partial:
        time.sleep(10)
    sys.exit(2)
''')
            cargo.chmod(0o755)
            env = os.environ.copy()
            env['PATH'] = str(root / 'bin') + os.pathsep + env['PATH']
            result = subprocess.run([sys.executable, '-B', str(root / 'scripts/mutants_gate.py'),
                                     'HEAD', 'linux', '0'], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('critical src/store.rs', result.stdout)
            self.assertIn('changed src/main.rs', result.stdout)
            self.assertIn('caught=1, missed=1', result.stdout)
            self.assertIn('missed mutants: src/store.rs:1:1: critical mutation', result.stderr)
            config_path = root / '.cargo/mutants-gate.toml'
            config_path.write_text(config_path.read_text().replace('budget_seconds = 60', 'budget_seconds = 1'))
            env['FAKE_MUTANT_WAIT'] = '1'
            result = subprocess.run([sys.executable, '-B', str(root / 'scripts/mutants_gate.py'),
                                     'HEAD', 'linux', '0'], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('budget exhausted', result.stderr)

            config_path.write_text(config_path.read_text().replace('budget_seconds = 1', 'budget_seconds = 3'))
            del env['FAKE_MUTANT_WAIT']
            env['FAKE_PARTIAL'] = '1'
            result = subprocess.run([sys.executable, '-B', str(root / 'scripts/mutants_gate.py'),
                                     'HEAD', 'linux', '0'], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('caught=1, missed=0', result.stdout)
            self.assertIn('budget exhausted; 1 unresolved: src/store.rs:1:1: critical mutation', result.stderr)


if __name__ == '__main__':
    unittest.main()
