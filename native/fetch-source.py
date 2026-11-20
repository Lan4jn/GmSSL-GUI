#!/usr/bin/env python3
"""Fetch an isolated, immutable upstream checkout; never edit a supplied checkout."""
import argparse
import hashlib
import json
import pathlib
import subprocess

COMMIT = '24ae482701a7b124826c382fffc55c19f76d475d'
URL = 'https://github.com/guanzhi/GmSSL.git'


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], stderr=subprocess.PIPE)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=pathlib.Path, help='verify an existing checkout read-only')
    args = parser.parse_args()
    target = args.source or pathlib.Path(__file__).resolve().parent / '.cache' / 'upstream'
    if target.is_symlink():
        raise SystemExit('source directory is a symlink')
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'init', str(target)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['git', '-C', str(target), 'fetch', '--depth=1', URL, COMMIT], check=True)
        subprocess.run(['git', '-C', str(target), 'checkout', '--detach', 'FETCH_HEAD'], check=True)
    actual = git(target, 'rev-parse', 'HEAD').decode().strip()
    if actual != COMMIT or git(target, 'status', '--porcelain', '--untracked-files=no').strip():
        raise SystemExit('source identity or cleanliness mismatch')
    archive = git(target, 'archive', '--format=tar', COMMIT)
    identity = {'sourceCommit': actual, 'tree': git(target, 'rev-parse', 'HEAD^{tree}').decode().strip(),
                'archiveSha256': hashlib.sha256(archive).hexdigest(), 'repository': URL}
    print(json.dumps(identity, sort_keys=True))


if __name__ == '__main__':
    main()
