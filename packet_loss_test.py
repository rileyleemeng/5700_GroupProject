#!/usr/bin/env python3
import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path


def md5_file(path: Path) -> str:
    h = hashlib.md5()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, *, cwd=None, check=True, capture=True):
    print(f"[RUN] {' '.join(shlex.quote(str(x)) for x in cmd)}")
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        text=True,
        capture_output=capture,
    )


def tc_add(interface: str, loss: str, delay: str | None):
    cmd = ['tc', 'qdisc', 'replace', 'dev', interface, 'root', 'netem', 'loss', loss]
    if delay:
        cmd += ['delay', delay]
    run(cmd, capture=False)


def tc_del(interface: str):
    try:
        run(['tc', 'qdisc', 'del', 'dev', interface, 'root'], check=False, capture=False)
    except Exception:
        pass


def terminate_process(proc: subprocess.Popen, name: str):
    if proc.poll() is not None:
        return
    print(f"[CLEANUP] Terminating {name} (pid={proc.pid})")
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def parse_server_report(report_path: Path):
    data = {}
    if not report_path.exists():
        return data
    for line in report_path.read_text(errors='replace').splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            data[k.strip('- ').strip()] = v.strip()
    return data


def main():
    parser = argparse.ArgumentParser(description='Automatic Phase 1 packet-loss test runner')
    parser.add_argument('--project-dir', default='.', help='directory containing server.py/client.py')
    parser.add_argument('--filename', required=True, help='file to request from server')
    parser.add_argument('--server-ip', default='127.0.0.1')
    parser.add_argument('--client-ip', default='127.0.0.1')
    parser.add_argument('--server-port', type=int, default=12000)
    parser.add_argument('--client-port', type=int, default=12001)
    parser.add_argument('--interface', default='lo', help='network interface for tc netem, e.g. lo or eth0')
    parser.add_argument('--loss', default='3%', help='packet loss rate, e.g. 3%%')
    parser.add_argument('--delay', default='40ms', help='optional netem delay, e.g. 40ms')
    parser.add_argument('--window-size', type=int, default=16)
    parser.add_argument('--timeout', type=float, default=0.4)
    parser.add_argument('--max-idle-timeouts', type=int, default=20)
    parser.add_argument('--output', default=None, help='downloaded file path')
    parser.add_argument(
        '--simulate-drop-once',
        type=int,
        default=None,
        help='use the built-in server drop hook instead of tc loss if desired'
    )
    parser.add_argument('--skip-tc', action='store_true', help='do not apply tc netem; useful with --simulate-drop-once')
    parser.add_argument('--startup-wait', type=float, default=1.0)
    parser.add_argument('--client-timeout-seconds', type=int, default=120)
    args = parser.parse_args()

    project_dir = Path(args.project_dir).resolve()
    filename = Path(args.filename)
    if not filename.is_absolute():
        filename = (project_dir / filename).resolve()
    if not filename.exists():
        print(f"[ERROR] File not found: {filename}")
        sys.exit(1)

    output_path = Path(args.output).resolve() if args.output else (project_dir / f"downloaded_{filename.name}").resolve()
    server_log = project_dir / 'auto_test_server.log'
    client_log = project_dir / 'auto_test_client.log'
    summary_json = project_dir / 'auto_test_summary.json'
    server_report = project_dir / 'server_report.txt'
    client_report = project_dir / 'client_report.txt'

    for p in [server_log, client_log, summary_json, server_report, client_report, output_path]:
        try:
            if p.exists():
                p.unlink()
        except IsADirectoryError:
            pass

    server_cmd = [
        sys.executable, 'server.py', args.server_ip,
        '--port', str(args.server_port),
        '--window-size', str(args.window_size),
        '--timeout', str(args.timeout),
    ]
    if args.simulate_drop_once is not None:
        server_cmd += ['--simulate-drop-once', str(args.simulate_drop_once)]

    client_cmd = [
        sys.executable, 'client.py',
        '--server-port', str(args.server_port),
        '--client-port', str(args.client_port),
        '--timeout', str(args.timeout),
        '--max-idle-timeouts', str(args.max_idle_timeouts),
        '--output', str(output_path),
        filename.name,
        args.server_ip,
        args.client_ip,
    ]

    server_proc = None
    tc_enabled = False
    client_rc = None
    duration = 0.0
    start_ts = time.time()

    try:
        print('[INFO] Starting server...')
        sf = server_log.open('w')
        server_proc = subprocess.Popen(
            server_cmd,
            cwd=project_dir,
            stdout=sf,
            stderr=subprocess.STDOUT,
            text=True
        )
        time.sleep(args.startup_wait)

        if server_proc.poll() is not None:
            print('[ERROR] Server exited immediately. Check auto_test_server.log')
            sys.exit(2)

        if not args.skip_tc:
            print(f"[INFO] Applying tc netem on {args.interface}: loss={args.loss}, delay={args.delay}")
            tc_add(args.interface, args.loss, args.delay)
            tc_enabled = True

        print('[INFO] Starting client...')
        cf = client_log.open('w')
        try:
            client_completed = subprocess.run(
                client_cmd,
                cwd=project_dir,
                stdout=cf,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.client_timeout_seconds,
            )
            client_rc = client_completed.returncode
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
    output_exists = output_path.exists()
    downloaded_md5 = md5_file(output_path) if output_exists else None
    md5_match = output_exists and (original_md5 == downloaded_md5)

    server_report_data = parse_server_report(server_report)
    client_report_data = parse_server_report(client_report)

    summary = {
        'success': bool(md5_match and client_rc == 0),
        'file_requested': filename.name,
        'original_file': str(filename),
        'downloaded_file': str(output_path),
        'downloaded_exists': output_exists,
        'original_md5': original_md5,
        'downloaded_md5': downloaded_md5,
        'md5_match': md5_match,
        'client_return_code': client_rc,
        'loss': None if args.skip_tc else args.loss,
        'delay': None if args.skip_tc else args.delay,
        'interface': None if args.skip_tc else args.interface,
        'simulate_drop_once': args.simulate_drop_once,
        'duration_seconds': round(duration, 3),
        'server_log': str(server_log),
        'client_log': str(client_log),
        'server_report': server_report_data,
        'client_report': client_report_data,
    }
    summary_json.write_text(json.dumps(summary, indent=2))

    print('\n===== PHASE 1 TEST SUMMARY =====')
    print(f"Requested file   : {filename.name}")
    print(f"Downloaded file  : {output_path}")
    print(f"Client rc        : {client_rc}")
    print(f"Original MD5     : {original_md5}")
    print(f"Downloaded MD5   : {downloaded_md5}")
    print(f"MD5 match        : {md5_match}")
    print(f"Duration (sec)   : {round(duration, 3)}")
    if not args.skip_tc:
        print(f"tc netem         : interface={args.interface}, loss={args.loss}, delay={args.delay}")
    if args.simulate_drop_once is not None:
        print(f"simulate_drop    : seq={args.simulate_drop_once}")
    print(f"Server log       : {server_log}")
    print(f"Client log       : {client_log}")
    print(f"Summary JSON     : {summary_json}")

    if md5_match and client_rc == 0:
        print('[RESULT] PASS')
        sys.exit(0)
    else:
        print('[RESULT] FAIL')
        sys.exit(3)


if __name__ == '__main__':
    main()