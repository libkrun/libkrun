#!/usr/bin/env python3
"""Compare bytes accepted before shutdown with bytes received before TCP EOF.

Compile guest.rs for the host's Linux musl architecture. Set SMOL_UDP_PROBE,
SMOL_UDP_LAUNCHER, SMOL_UDP_KERNEL, SMOL_UDP_LIBRARY and SMOL_UDP_LIB_DIR to
isolated probe/launcher/kernel/runtime artifacts, or use --native on Linux.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import traceback

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('out', type=pathlib.Path)
parser.add_argument('--native', action='store_true')
args = parser.parse_args()
if args.native and sys.platform != 'linux':
    parser.error('native baseline requires Linux')
args.out.mkdir(parents=True, exist_ok=False)
config, sockets, threads, results, errors = [], [], [], [], []
stop = threading.Event()


def accept(listener):
    while not stop.is_set():
        try:
            return listener.accept()[0]
        except socket.timeout:
            continue
    raise RuntimeError('probe stopped before connecting')


def receive(name, data_listener, control_listener, both):
    try:
        with accept(data_listener) as data, accept(control_listener) as control:
            data.settimeout(5)
            control.settimeout(5)
            expected = b''
            while len(expected) < 8:
                chunk = control.recv(8 - len(expected))
                if not chunk:
                    raise RuntimeError('truncated control message')
                expected += chunk
            expected = int.from_bytes(expected, 'little')
            received = 0
            valid = True
            while True:
                chunk = data.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
                valid = valid and chunk == b'S' * len(chunk)
            results.append(dict(name=name, expected=expected, received=received,
                                passed=valid and expected == received))
            if not both:
                data.sendall(received.to_bytes(8, 'little'))
                data.shutdown(socket.SHUT_WR)
            control.sendall(received.to_bytes(8, 'little'))
    except Exception:
        errors.append(dict(name=name, error=traceback.format_exc()))


try:
    for family, ip, label in [(socket.AF_INET, '127.0.0.1', 'v4'),
                              (socket.AF_INET6, '::1', 'v6')]:
        for size in [0, 8192, 32 * 1024 * 1024]:
            for both in [False, True]:
                mode = 'both' if both else 'write'
                name = '%s-%s-%d' % (label, mode, size)
                pair = []
                peers = []
                for _ in range(2):
                    listener = socket.socket(family, socket.SOCK_STREAM)
                    sockets.append(listener)
                    listener.bind((ip, 0))
                    listener.listen(1)
                    listener.settimeout(.1)
                    pair.append(listener)
                    peers.append(('[%s]:%d' if family == socket.AF_INET6 else '%s:%d') %
                                 (ip, listener.getsockname()[1]))
                config.append('%s %s %s %d %s' % (name, *peers, size, mode))
                thread = threading.Thread(target=receive, args=(name, *pair, both))
                threads.append(thread)
                thread.start()
    with tempfile.TemporaryDirectory(prefix='smol-tcp-close-') as tmp:
        root = pathlib.Path(tmp)
        shutil.copy2(os.environ['SMOL_UDP_PROBE'], root / 'probe')
        (root / 'probe').chmod(0o755)
        (root / 'close-config').write_text('\n'.join(config) + '\n')
        env = os.environ.copy()
        env.update(SMOL_HOST_MODE='host', SMOL_DNS_FORWARDER='127.0.0.1:9')
        env.pop('SMOL_TCP_INTERCEPT', None)
        if args.native:
            command = [str(root / 'probe')]
        else:
            library = pathlib.Path(env['SMOL_UDP_LIBRARY']).resolve()
            search = os.pathsep.join([str(library.parent), env['SMOL_UDP_LIB_DIR']])
            env.update(LD_LIBRARY_PATH=search, DYLD_LIBRARY_PATH=search,
                       DYLD_FALLBACK_LIBRARY_PATH='/Library/Developer/CommandLineTools/usr/lib')
            command = [env['SMOL_UDP_LAUNCHER'], str(root), env['SMOL_UDP_KERNEL'], str(library)]
        try:
            with (args.out / 'run.log').open('w') as log:
                code = subprocess.run(command, cwd=root, env=env, stdout=log,
                                      stderr=subprocess.STDOUT, timeout=60).returncode
        except subprocess.TimeoutExpired:
            code = -1
finally:
    stop.set()
    for thread in threads:
        thread.join(timeout=6)
    for listener in sockets:
        listener.close()
log = (args.out / 'run.log').read_text()
cases = [line.split() for line in log.splitlines() if line.startswith('CLOSE_CASE ')]
loaded = [line[len('SMOL_RUNTIME_LIBRARY '):] for line in log.splitlines()
          if line.startswith('SMOL_RUNTIME_LIBRARY ')]
verified = args.native or (len(loaded) == 1 and pathlib.Path(loaded[0]).resolve() == library)
passed = (code == 0 and verified and not errors and len(results) == len(config)
          and all(r['passed'] for r in results)
          and [c[1] for c in cases] == [c.split()[0] for c in config]
          and all(c[2] == 'PASS' for c in cases))
report = dict(passed=passed, exit=code, cases=results, errors=errors, runtime_verified=verified,
              hashes={k: hashlib.sha256(pathlib.Path(env[k]).read_bytes()).hexdigest()
                      for k in ['SMOL_UDP_PROBE', 'SMOL_UDP_LIBRARY', 'SMOL_UDP_KERNEL'] if k in env})
(args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
sys.exit(0 if passed else 1)
