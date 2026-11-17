import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / '.cargo/mutants-gate.toml'
WORK = ROOT / '.work/mutants-gate'
GATE = {'Makefile', '.github/workflows/ci.yml', '.cargo/mutants.toml',
        '.cargo/mutants-gate.toml', 'scripts/mutants_gate.py', 'scripts/test_mutants_gate.py'}


class GateError(Exception):
    pass


class BudgetExhausted(GateError):
    pass


def budget_message(pending):
    shown = ', '.join(pending[:10])
    more = f' and {len(pending) - 10} more' if len(pending) > 10 else ''
    return f'budget exhausted; {len(pending)} unresolved: {shown}{more}'


def classify(path, status, config):
    if path in GATE:
        return 'gate'
    if any(fnmatch.fnmatchcase(path, pattern) for pattern in config['irrelevant']):
        return 'irrelevant'
    if path.startswith('src/') and path.endswith('.rs'):
        return 'deleted production' if status == 'D' else 'production'
    if path.startswith('src/') and path.endswith('.swift'):
        return 'deleted production' if status == 'D' else 'unsupported production'
    if path.endswith('.rs') and not path.startswith('src/'):
        return 'tests'
    if path.startswith(('tests/', 'fixtures/')):
        return 'fixtures'
    if path in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain', 'rust-toolchain.toml', 'build.rs', 'Dockerfile', '.gitignore', '.dockerignore', 'clippy.toml', 'scripts/install-rage.sh'} or path.startswith(('.cargo/', '.github/workflows/')) or Path(path).name in {'Cargo.toml', 'Cargo.lock', 'build.rs'}:
        return 'build configuration'
    return 'unclassified'


def scope_for(classes, config):
    unknown = sorted(path for path, kind in classes.items() if kind in {'unclassified', 'unsupported production'})
    if unknown:
        raise GateError('unclassified paths: ' + ', '.join(unknown))
    triggers = {'tests', 'fixtures', 'build configuration', 'gate', 'deleted production'}
    if any(kind in triggers for kind in classes.values()):
        if not config['scope']:
            raise GateError('empty configured critical scope')
        return set(config['scope'])
    return set()


def parse_changes(data):
    fields = data.split('\0')
    changes = {}
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        i += 1
        if status[0] in 'RC':
            old, new = fields[i:i + 2]
            i += 2
            changes[old] = 'D' if status[0] == 'R' else 'M'
            changes[new] = 'A'
        else:
            changes[fields[i]] = status[0]
            i += 1
    return changes


def read_results(path, selected, *, baseline=True, complete=True):
    try:
        data = json.loads(path.read_text())
        outcomes = data['outcomes']
        if not isinstance(outcomes, list):
            raise ValueError('outcomes is not a list')
        results = {}
        baselines = 0
        summaries = {'CaughtMutant': 'caught', 'MissedMutant': 'missed', 'Timeout': 'timeout', 'Unviable': 'unviable'}
        for outcome in outcomes:
            scenario = outcome['scenario']
            if scenario == 'Baseline':
                if outcome['summary'] != 'Success':
                    raise ValueError('baseline failed')
                baselines += 1
                baseline_log = Path(outcome['log_path'])
                if baseline_log.is_absolute() or '..' in baseline_log.parts:
                    raise ValueError('invalid baseline log path')
                (path.parent / baseline_log).read_text()
                continue
            name = scenario['Mutant']['name']
            summary = summaries[outcome['summary']]
            log = Path(outcome['log_path'])
            if log.is_absolute() or '..' in log.parts:
                raise ValueError('invalid log path')
            log_text = (path.parent / log).read_text()
            if any(marker in log_text for marker in ('VAULT_HARNESS_ERROR:', '\nfixture compile', '\ncompile fault library')):
                raise ValueError(f'harness error invalidates mutant: {name}')
            if name in results:
                raise ValueError('duplicate mutant')
            results[name] = summary
        if baselines != int(baseline):
            raise ValueError('missing or duplicate baseline')
        if (not results.keys() <= set(selected) or
                (complete and len(results) != len(selected)) or data['total_mutants'] != len(results)):
            raise ValueError('tested count or identities differ from selection')
        for kind in summaries.values():
            if data[kind] != list(results.values()).count(kind):
                raise ValueError('summary count mismatch')
        return results
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise GateError(f'incomplete result: {path}: {error}') from error


def verdict(results):
    if 'missed' in results.values():
        raise GateError('missed mutants: ' + ', '.join(n for n, v in results.items() if v == 'missed'))
    if 'timeout' in results.values():
        raise GateError('unresolved timeout: ' + ', '.join(n for n, v in results.items() if v == 'timeout'))


def parse_entries(text):
    if not text.strip():
        return []
    try:
        entries = json.loads(text)
        if not isinstance(entries, list):
            raise ValueError('listing is not an array')
        names = [entry['name'] for entry in entries]
    except (ValueError, KeyError, TypeError) as error:
        raise GateError(f'selection error: {error}') from error
    if len(set(names)) != len(names):
        raise GateError('selection error: duplicate mutant names')
    return entries


def parse_listing(text):
    return [entry['name'] for entry in parse_entries(text)]


def partition(names, shards, index, limit):
    if shards < 1 or not 0 <= index < shards:
        raise GateError('invalid shard')
    names = sorted(names)
    if len(names) != len(set(names)):
        raise GateError('duplicate identity in union')
    if (len(names) + shards - 1) // shards > limit:
        raise GateError(f'shard capacity exceeded: {len(names)} identities')
    return names[index::shards]


def regex_for(names):
    return '^(?:' + '|'.join(re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', n) for n in names) + ')$'


def platform_files(platform):
    if platform == 'linux':
        return {'src/main.rs', 'src/store.rs', 'src/linux.rs'}
    if platform == 'macos':
        return {'src/main.rs', 'src/store.rs', 'src/macos.rs', 'src/secure_enclave.rs'}
    raise GateError(f'unsupported platform: {platform}')


def active_mutant(entry, platform, source):
    """Route known target_os attributes; reject new attribute forms for review."""
    path = entry['file']
    if path not in platform_files(platform):
        return False
    if path not in {'src/main.rs', 'src/store.rs'}:
        for line in source.splitlines()[:test_module_line(source) - 1]:
            if '#[cfg' in line and line.strip() != '#[cfg(test)]':
                raise GateError(f'unsupported cfg in {path}: {line.strip()}')
        return True
    lines = source.splitlines()
    end = test_module_line(source) - 1
    target_line = entry['span']['start']['line']
    function = entry['function']
    if function is None:
        if not re.match(r'(?:pub(?:\(crate\))? )?const \w+\b.*;\s*$', lines[target_line - 1].strip()):
            raise GateError(f'unsupported non-function mutation: {entry["name"]}')
        function_line = None
    else:
        function_line = function['span']['start']['line']
    active = True
    for i, line in enumerate(lines[:end]):
        if '#[cfg' not in line:
            continue
        attribute = line.strip()
        if attribute in {'#[cfg(unix)]', '#[cfg(any(target_os = "linux", target_os = "macos"))]',
                         '#[cfg(not(any(target_os = "macos", target_os = "linux")))]',
                         '#[cfg(all(test, target_os = "macos"))]'}:
            continue
        if attribute.startswith('enum CommandKind ') and '#[cfg(target_os = "macos")] Recover' in attribute:
            continue
        match = re.fullmatch(r'#\[cfg\(target_os = "(linux|macos)"\)\]', attribute)
        if not match:
            raise GateError(f'unsupported cfg in {path}:{i + 1}: {attribute}')
        j = i + 1
        while j < end and not lines[j].strip():
            j += 1
        if j >= end:
            raise GateError(f'cfg without item in {path}:{i + 1}')
        item = lines[j].strip()
        applies = False
        if re.match(r'(?:pub\(crate\) )?fn ', item):
            applies = function_line in {i + 1, j + 1}
        elif item == 'if args[0] == storage::CACHE_DAEMON_ARG {':
            k = j + 1
            while k < end and lines[k] != '    }':
                if '{' in lines[k] or '}' in lines[k]:
                    raise GateError(f'unsupported nested cfg block in {path}:{j + 1}')
                k += 1
            if k == end:
                raise GateError(f'unterminated cfg block in {path}:{j + 1}')
            applies = j + 1 <= target_line <= k + 1
        elif item.startswith(('mod ', 'use ', 'const ', 'pub(crate) const ', 'CommandSpec {', 'CommandKind::Recover =>',
                              'crate::store::validate_name(')):
            applies = target_line == j + 1
        else:
            raise GateError(f'unsupported cfg item in {path}:{j + 1}: {item}')
        if applies and match.group(1) != platform:
            active = False
    return active


def selected_or_fail(relevant, names):
    if relevant and not names:
        raise GateError('unexpected empty selection')


def test_module_line(source):
    lines = source.splitlines()
    for i, line in enumerate(lines[:-1]):
        if line.strip() == '#[cfg(test)]' and lines[i + 1].strip() == 'mod tests {':
            return i + 1
    return 10**9


def hunk_ownership(diff, old_line, new_line):
    production = tests = False
    for match in re.finditer(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', diff, re.M):
        old_start, old_count = int(match[1]), int(match[2] or '1')
        new_start, new_count = int(match[3]), int(match[4] or '1')
        production |= (old_count > 0 and old_start < old_line) or (new_count > 0 and new_start < new_line)
        tests |= (old_count > 0 and old_start + old_count - 1 >= old_line) or (new_count > 0 and new_start + new_count - 1 >= new_line)
    return production, tests


def main():
    started = time.monotonic()
    config = tomllib.loads(CONFIG.read_text())
    deadline = started + config['budget_seconds']
    WORK.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix='run-', dir=WORK))
    if len(sys.argv) != 4:
        raise GateError('usage: mutants_gate.py BASE linux|macos SHARD')
    base, platform, shard_arg = sys.argv[1:]
    shard = int(shard_arg)
    allowed_files = platform_files(platform)
    common = ['cargo', 'mutants', '--gitignore', 'true']
    phases = []
    counts = {'caught': 0, 'missed': 0, 'unviable': 0, 'timeout': 0, 'confirmed hang': 0}
    hangs = []
    base_sha = head = version = host = 'unavailable'
    excluded = 'unavailable'
    dirty = ''
    pending = []

    def cancel(signum, _frame):
        raise GateError(f'interrupted by signal {signum}')

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, cancel)

    def run(args, *, allowed=(0,), capture=True):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BudgetExhausted(budget_message(pending))
        process = subprocess.Popen(args, cwd=ROOT, text=True, stdout=subprocess.PIPE if capture else None,
                                   stderr=subprocess.PIPE if capture else None, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise BudgetExhausted(budget_message(pending)) from error
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        if process.returncode not in allowed:
            raise GateError(f'command failed ({process.returncode}): {args}: {stderr or ""}')
        return stdout if capture else ''

    def entries(args):
        return parse_entries(run(common + ['--list', '--json'] + args))

    def listing(args):
        return [entry['name'] for entry in entries(args)]

    try:
        base_sha = run(['git', 'merge-base', base, 'HEAD']).strip()
        head = run(['git', 'rev-parse', 'HEAD']).strip()
        dirty = ' dirty' if run(['git', 'status', '--porcelain', '--untracked-files=normal']).strip() else ''
        host = next(line for line in run(['rustc', '-vV']).splitlines() if line.startswith('host:'))
        changes = parse_changes(run(['git', 'diff', '--merge-base', base, '--name-status', '-M', '-z']))
        for path in run(['git', 'ls-files', '--others', '--exclude-standard', '-z']).split('\0'):
            if path:
                changes[path] = 'A'
        classes = {path: classify(path, status, config) for path, status in changes.items()}
        for path, kind in sorted(classes.items()):
            print(f'{kind}: {path}', flush=True)
        whole = scope_for(classes, config)
        actual_platform = 'macos' if 'apple-darwin' in host else 'linux' if 'linux' in host else 'unsupported'
        if platform != actual_platform:
            raise GateError(f'platform {platform} does not match {host}')
        known = platform_files('linux') | platform_files('macos')
        unknown_source = sorted(p for p, kind in classes.items() if kind == 'production' and p not in known)
        if unknown_source:
            raise GateError('unmapped production paths: ' + ', '.join(unknown_source))
        diffs = {}
        ownership = {}
        for path, kind in classes.items():
            if kind != 'production':
                continue
            diff = run(['git', 'diff', '--merge-base', base, '--no-ext-diff', '--unified=0', '--', path])
            if not diff and changes[path] == 'A':
                diff = run(['git', 'diff', '--no-index', '--', '/dev/null', path], allowed=(0, 1))
            old = run(['git', 'show', f'{base_sha}:{path}'], allowed=(0, 128))
            current = (ROOT / path).read_text()
            old_line = test_module_line(old)
            new_line = test_module_line(current)
            ownership[path] = hunk_ownership(diff, old_line, new_line)
            diffs[path] = diff
            if ownership[path][1]:
                whole.update(config['scope'])
        union = {}
        sources = {}

        def add(label, candidates):
            active_count = 0
            for item in candidates:
                path = item['file']
                if path not in known:
                    raise GateError(f'unmapped mutant source: {path}')
                if path not in allowed_files:
                    continue
                if path not in sources:
                    sources[path] = (ROOT / path).read_text()
                if active_mutant(item, platform, sources[path]):
                    name = item['name']
                    union.setdefault(name, set()).add(label)
                    active_count += 1
                else:
                    print(f'inactive on {platform}: {item["name"]}', flush=True)
            return active_count

        if whole:
            if platform == 'linux':
                for path in sorted(whole):
                    if not add('critical ' + path, entries(['-f', path])):
                        raise GateError(f'empty critical scope: {path}')
            extra_scope = config.get(platform + '_critical')
            if not extra_scope:
                raise GateError(f'empty configured {platform} critical scope')
            for critical in extra_scope:
                label = 'critical ' + critical['file'] + ' ' + critical['function']
                if not add(label, entries(['-f', critical['file'], '-F', critical['function']])):
                    raise GateError(f'empty {label}')
        for path, kind in classes.items():
            if kind != 'production':
                continue
            if path not in allowed_files:
                print(f'production routed to other platform: {path}', flush=True)
                continue
            has_production, has_tests = ownership[path]
            if not has_production and has_tests:
                continue
            diff = diffs[path]
            file_diff = run_root / 'file.diff'
            file_diff.write_text(diff)
            selected = entries(['--in-diff', str(file_diff)])
            if not selected:
                selected = entries(['-f', path])
            if not selected:
                raise GateError(f'unexpected empty production selection: {path}')
            if not add('changed ' + path, selected):
                if not add('changed file fallback ' + path, entries(['-f', path])):
                    raise GateError(f'no active mutations in production file: {path}')
        relevant = any(k != 'irrelevant' for k in classes.values())
        platform_relevant = bool(whole) or any(k == 'production' and p in allowed_files for p, k in classes.items())
        if platform_relevant:
            selected_or_fail(True, list(union))
        elif not relevant:
            print('irrelevant change: no mutants selected', flush=True)
        else:
            print('no relevant change for this platform', flush=True)
        selected = partition(list(union), config['shards'], shard, config['max_per_shard'])
        inventory = {name: sorted(labels) for name, labels in sorted(union.items())}
        (run_root / 'inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
        print(f'artifacts: {run_root}', flush=True)
        print(f'platform: {platform}; union: {len(union)}; shard: {shard}/{config["shards"]}; selected: {len(selected)}', flush=True)
        for name in selected:
            print(f'  {name}: {", ".join(inventory[name])}', flush=True)
        if not selected:
            return
        args = ['--re', regex_for(selected)]
        if set(listing(args)) != set(selected):
            raise GateError('shard identity selection differs from union')
        phases.append((f'{platform} shard {shard}', args, selected))
        version = run(common + ['--version']).strip()
        configured = set(listing([]))
        unconfigured = set(listing(['--no-config']))
        excluded = str(len(unconfigured - configured))
        for index, (label, args, names) in enumerate(phases):
            pending[:] = [n for _, _, ns in phases[index:] for n in ns]
            print(f'phase: {label}; selected {len(names)}', flush=True)
            out = run_root / f'phase-{index}'
            receipt = out / 'mutants.out/outcomes.json'
            budget_error = None
            try:
                run(common + ['--baseline', 'run', '--timeout', str(config['timeout_seconds']),
                    '--build-timeout', str(config['build_timeout_seconds']), '--jobs', str(config['jobs']),
                    '--output', str(out)] + args, allowed=(0, 2, 3), capture=False)
            except BudgetExhausted as error:
                if not receipt.is_file():
                    raise
                budget_error = error
            results = read_results(receipt, names, complete=budget_error is None)
            for name, result in results.items():
                counts[result] += 1
                if result != 'timeout':
                    pending.remove(name)
            if budget_error is not None:
                raise BudgetExhausted(budget_message(pending)) from budget_error
            for number, name in enumerate(n for n, v in results.items() if v == 'timeout'):
                regex = '^' + re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', name) + '$'
                retry_args = ['--re', regex]
                if listing(retry_args) != [name]:
                    raise GateError(f'timeout rerun selection error: {name}')
                out = run_root / f'retry-{index}-{number}'
                run(common + ['--baseline', 'skip', '--timeout', str(config['timeout_seconds'] * 3),
                    '--build-timeout', str(config['build_timeout_seconds']), '--jobs', '1',
                    '--output', str(out)] + retry_args, allowed=(0, 2, 3), capture=False)
                rerun = read_results(out / 'mutants.out/outcomes.json', [name], baseline=False)[name]
                counts['timeout'] -= 1
                if rerun == 'timeout':
                    results[name] = 'confirmed hang'
                    hangs.append(name)
                    counts['confirmed hang'] += 1
                else:
                    results[name] = rerun
                    counts[rerun] += 1
                pending.remove(name)
            verdict(results)
    finally:
        print('\nEvidence:', flush=True)
        print(f'base: {base_sha}; head: {head}{dirty}; {version}', flush=True)
        print(f'config sha256: {hashlib.sha256(CONFIG.read_bytes()).hexdigest()}; excluded mutants: {excluded}', flush=True)
        print(f'{host}; features: default', flush=True)
        for label, _, names in phases:
            print(f'phase: {label}; selected: {len(names)}', flush=True)
        print('counts: ' + ', '.join(f'{k}={v}' for k, v in counts.items()), flush=True)
        print('confirmed hangs: ' + (', '.join(hangs) if hangs else 'none'), flush=True)
        print(f'wall time: {time.monotonic() - started:.1f}s', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (GateError, OSError, ValueError, StopIteration) as error:
        print(f'gate failure: {error}', file=sys.stderr)
        sys.exit(1)
