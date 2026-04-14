#!/usr/bin/env python3
"""Run SRFT tests with tc netem and optional built-in attack modes."""

import argparse
import hashlib
import json
import signal
import subprocess
import sys
import time
from pathlib import Path


def md5_file(path: Path):
    if not path.exists():
        return None
    h = hashlib.md5()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path: Path):
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def tc_add(interface: str, loss: str, delay: str):
    subprocess.run(['sudo', 'tc', 'qdisc', 'replace', 'dev', interface, 'root', 'netem', 'loss', loss, 'delay', delay], check=True)


def tc_del(interface: str):
    subprocess.run(['sudo', 'tc', 'qdisc', 'del', 'dev', interface, 'root'], check=False)


def terminate_process(proc: subprocess.Popen, name: str):
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def parse_report(report_path: Path):
    if not report_path.exists():
        return None
    out = {}
    for line in report_path.read_text(errors='replace').splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            out[k.strip()] = v.strip()
    return out


def main():
    parser = argparse.ArgumentParser(description='SRFT Phase1/Phase2 test runner')
    parser.add_argument('--project-dir', default='.')
    parser.add_argument('--filename', required=True)
    parser.add_argument('--server-ip', default='127.0.0.1')
    parser.add_argument('--client-ip', default='127.0.0.1')
    parser.add_argument('--server-port', type=int, default=12000)
    parser.add_argument('--client-port', type=int, default=12001)
    parser.add_argument('--interface', default='lo')
    parser.add_argument('--loss', default='3%')
    parser.add_argument('--delay', default='40ms')
    parser.add_argument('--window-size', type=int, default=8)
    parser.add_argument('--timeout', type=float, default=0.5)
    parser.add_argument('--max-idle-timeouts', type=int, default=20)
    parser.add_argument('--receiver-window', type=int, default=64)
    parser.add_argument('--ack-every', type=int, default=2)
    parser.add_argument('--psk-file', default=None)
    parser.add_argument('--attack', choices=['none', 'tamper', 'replay', 'inject'], default='none')
    parser.add_argument('--attack-seq', type=int, default=0)
    parser.add_argument('--output', default=None)
    parser.add_argument('--skip-tc', action='store_true')
    parser.add_argument('--startup-wait', type=float, default=1.0)
    parser.add_argument('--client-timeout-seconds', type=int, default=120)
    args = parser.parse_args()

    project_dir = Path(args.project_dir).resolve()
    filename = Path(args.filename)
    if not filename.is_absolute():
        filename = (project_dir / filename).resolve()
    if not filename.exists():
        print(f'[ERROR] File not found: {filename}')
        sys.exit(1)

    output_path = Path(args.output).resolve() if args.output else (project_dir / f'downloaded_{filename.name}').resolve()
    server_log = project_dir / 'auto_test_server.log'
    client_log = project_dir / 'auto_test_client.log'
    summary_json = project_dir / 'auto_test_summary.json'
    server_report = project_dir / 'server_report.txt'
    client_report = project_dir / 'client_report.txt'

    for p in [server_log, client_log, summary_json, server_report, client_report, output_path]:
        if p.exists() and p.is_file():
            p.unlink()

    server_cmd = [
        sys.executable, 'server.py',
        '--server-ip', args.server_ip,
        '--client-ip', args.client_ip,
        '--server-port', str(args.server_port),
        '--client-port', str(args.client_port),
        '--window-size', str(args.window_size),
        '--timeout', str(args.timeout),
        '--max-idle-timeouts', str(args.max_idle_timeouts),
        '--attack', args.attack,
        '--attack-seq', str(args.attack_seq),
    ]
    client_cmd = [
        sys.executable, 'client.py',
        filename.name,
        args.server_ip,
        args.client_ip,
        '--server-port', str(args.server_port),
        '--client-port', str(args.client_port),
        '--timeout', str(args.timeout),
        '--max-idle-timeouts', str(args.max_idle_timeouts),
        '--receiver-window', str(args.receiver_window),
        '--ack-every', str(args.ack_every),
        '--output', str(output_path),
    ]
    if args.psk_file:
        server_cmd += ['--psk-file', args.psk_file]
        client_cmd += ['--psk-file', args.psk_file]

    server_proc = None
    tc_enabled = False
    client_rc = None
    duration = 0.0
    start_ts = time.time()

    try:
        print('[INFO] Starting server...')
        sf = server_log.open('w')
        server_proc = subprocess.Popen(server_cmd, cwd=project_dir, stdout=sf, stderr=subprocess.STDOUT, text=True)
        time.sleep(args.startup_wait)
        if server_proc.poll() is not None:
            print('[ERROR] Server exited immediately. Check auto_test_server.log')
            sys.exit(2)
        if not args.skip_tc:
            print(f'[INFO] Applying tc netem on {args.interface}: loss={args.loss}, delay={args.delay}')
            tc_add(args.interface, args.loss, args.delay)
            tc_enabled = True
        print('[INFO] Starting client...')
        cf = client_log.open('w')
        try:
            completed = subprocess.run(client_cmd, cwd=project_dir, stdout=cf, stderr=subprocess.STDOUT, text=True, timeout=args.client_timeout_seconds)
            client_rc = completed.returncode
        except subprocess.TimeoutExpired:
            print('[ERROR] Client timed out')
            client_rc = 124
        duration = time.time() - start_ts
    finally:
        if tc_enabled:
            print('[INFO] Removing tc netem')
            tc_del(args.interface)
        if server_proc is not None:
            terminate_process(server_proc, 'server')

    original_md5 = md5_file(filename)
    downloaded_md5 = md5_file(output_path)
    original_sha256 = sha256_file(filename)
    downloaded_sha256 = sha256_file(output_path)
    md5_match = downloaded_md5 is not None and downloaded_md5 == original_md5
    sha256_match = downloaded_sha256 is not None and downloaded_sha256 == original_sha256

    summary = {
        'success': bool(client_rc == 0 and md5_match and sha256_match),
        'file_requested': filename.name,
        'original_file': str(filename),
        'downloaded_file': str(output_path),
        'original_md5': original_md5,
        'downloaded_md5': downloaded_md5,
        'md5_match': md5_match,
        'original_sha256': original_sha256,
        'downloaded_sha256': downloaded_sha256,
        'sha256_match': sha256_match,
        'client_return_code': client_rc,
        'loss': None if args.skip_tc else args.loss,
        'delay': None if args.skip_tc else args.delay,
        'interface': None if args.skip_tc else args.interface,
        'attack': args.attack,
        'attack_seq': args.attack_seq,
        'duration_seconds': round(duration, 3),
        'server_log': str(server_log),
        'client_log': str(client_log),
        'server_report': parse_report(server_report),
        'client_report': parse_report(client_report),
    }
    summary_json.write_text(json.dumps(summary, indent=2))

    print('\n===== SRFT TEST SUMMARY =====')
    print(f'Requested file   : {filename.name}')
    print(f'Downloaded file  : {output_path}')
    print(f'Client rc        : {client_rc}')
    print(f'MD5 match        : {md5_match}')
    print(f'SHA-256 match    : {sha256_match}')
    print(f'Duration (sec)   : {round(duration, 3)}')
    if not args.skip_tc:
        print(f'tc netem         : interface={args.interface}, loss={args.loss}, delay={args.delay}')
    print(f'attack           : {args.attack} seq={args.attack_seq}')
    print(f'Server log       : {server_log}')
    print(f'Client log       : {client_log}')
    print(f'Summary JSON     : {summary_json}')
    if summary['success']:
        print('[RESULT] PASS')
        sys.exit(0)
    print('[RESULT] FAIL')
    sys.exit(3)


if __name__ == '__main__':
    main()
