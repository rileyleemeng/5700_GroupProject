import os
import hashlib
import time
import subprocess
import sys

# ── helpers ──────────────────────────────────────────────────────────────────

def md5(filepath):
    return hashlib.md5(open(filepath, 'rb').read()).hexdigest()

def create_test_file(name, size_bytes, binary=False):
    """Create a test file of a given size."""
    if binary:
        with open(name, 'wb') as f:
            f.write(os.urandom(size_bytes))
    else:
        with open(name, 'w') as f:
            content = ('SRFT test data 1234567890\n') * (size_bytes // 26 + 1)
            f.write(content[:size_bytes])
    print(f'[SETUP] Created {name} ({size_bytes} bytes, binary={binary})')

def verify(original, downloaded, test_name):
    """Compare original and downloaded file by MD5."""
    print(f'\n[TEST] {test_name}')
    if not os.path.exists(downloaded):
        print(f'  FAIL — {downloaded} not found')
        return False
    h1 = md5(original)
    h2 = md5(downloaded)
    if h1 == h2:
        print(f'  PASS — MD5 match: {h1}')
        return True
    else:
        print(f'  FAIL — MD5 mismatch')
        print(f'    original:   {h1}')
        print(f'    downloaded: {h2}')
        return False

def check_report():
    """Verify server_report.txt exists and has all required fields."""
    print('\n[TEST] Transfer report check')
    required_fields = [
        'Name of the transferred file',
        'Size of the transferred file',
        'The number of packets sent from the server',
        'The number of retransmitted packets from the server',
        'The number of packets received from the client',
        'The time duration of the file transfer',
    ]
    if not os.path.exists('server_report.txt'):
        print('  FAIL — server_report.txt not found')
        return False
    content = open('server_report.txt').read()
    all_ok = True
    for field in required_fields:
        if field in content:
            print(f'  OK  — "{field}"')
        else:
            print(f'  FAIL — missing: "{field}"')
            all_ok = False
    return all_ok

def cleanup(files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)

# ── test cases ────────────────────────────────────────────────────────────────

def run_transfer(filename):
    """
    Run server + client as subprocesses.
    Returns (success, elapsed_seconds).
    NOTE: Start server manually in another terminal if you run tests individually.
    """
    downloaded = 'downloaded_' + os.path.basename(filename)
    if os.path.exists(downloaded):
        os.remove(downloaded)
    if os.path.exists('server_report.txt'):
        os.remove('server_report.txt')

    start = time.time()
    server = subprocess.Popen([sys.executable, 'server.py'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.3)  # give server time to bind

    client_result = subprocess.run(
        [sys.executable, 'client.py', filename],
        capture_output=True, text=True, timeout=30
    )
    elapsed = time.time() - start

    server.terminate()
    server.wait()

    print(f'\n  [CLIENT OUTPUT]\n{client_result.stdout.strip()}')
    if client_result.returncode != 0:
        print(f'  [CLIENT ERROR]\n{client_result.stderr.strip()}')

    return elapsed

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print('=' * 60)
    print('  SRFT UDP File Transfer — Integration Test Suite')
    print('=' * 60)

    results = {}

    # ── Test 1: Small text file (1 chunk) ────────────────────────────────────
    create_test_file('test_small.txt', 100)
    elapsed = run_transfer('test_small.txt')
    passed = verify('test_small.txt', 'downloaded_test_small.txt', 'Small file (100 B)')
    results['Small file'] = passed
    print(f'  Time: {elapsed:.2f}s')
    cleanup(['downloaded_test_small.txt'])

    # ── Test 2: Medium text file (multiple chunks) ────────────────────────────
    create_test_file('test_medium.txt', 50_000)
    elapsed = run_transfer('test_medium.txt')
    passed = verify('test_medium.txt', 'downloaded_test_medium.txt', 'Medium file (50 KB)')
    results['Medium file'] = passed
    print(f'  Time: {elapsed:.2f}s')
    cleanup(['downloaded_test_medium.txt'])

    # ── Test 3: Large text file (stress test) ────────────────────────────────
    create_test_file('test_large.txt', 500_000)
    elapsed = run_transfer('test_large.txt')
    passed = verify('test_large.txt', 'downloaded_test_large.txt', 'Large file (500 KB)')
    results['Large file'] = passed
    print(f'  Time: {elapsed:.2f}s')
    cleanup(['downloaded_test_large.txt'])

    # ── Test 4: Binary file ───────────────────────────────────────────────────
    create_test_file('test_binary.bin', 20_000, binary=True)
    elapsed = run_transfer('test_binary.bin')
    passed = verify('test_binary.bin', 'downloaded_test_binary.bin', 'Binary file (20 KB)')
    results['Binary file'] = passed
    print(f'  Time: {elapsed:.2f}s')
    cleanup(['downloaded_test_binary.bin'])

    # ── Test 5: Missing file (server error handling) ──────────────────────────
    print('\n[TEST] Missing file (server should handle gracefully)')
    server = subprocess.Popen([sys.executable, 'server.py'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.3)
    client_result = subprocess.run(
        [sys.executable, 'client.py', 'nonexistent_file.txt'],
        capture_output=True, text=True, timeout=10
    )
    server.terminate()
    server.wait()
    output = client_result.stdout + client_result.stderr
    if 'not found' in output.lower() or 'timeout' in output.lower() or client_result.returncode != 0:
        print('  PASS — server handled missing file gracefully')
        results['Missing file'] = True
    else:
        print('  FAIL — unexpected behavior for missing file')
        results['Missing file'] = False

    # ── Test 6: Transfer report ───────────────────────────────────────────────
    # Re-run a small transfer to ensure report is fresh
    create_test_file('test_report_check.txt', 200)
    run_transfer('test_report_check.txt')
    passed = check_report()
    results['Report format'] = passed
    cleanup(['downloaded_test_report_check.txt', 'test_report_check.txt'])

    # ── Summary ───────────────────────────────────────────────────────────────
    print('\n' + '=' * 60)
    print('  TEST SUMMARY')
    print('=' * 60)
    total = len(results)
    passed_count = sum(results.values())
    for name, ok in results.items():
        status = 'PASS' if ok else 'FAIL'
        print(f'  [{status}]  {name}')
    print('-' * 60)
    print(f'  {passed_count}/{total} tests passed')
    print('=' * 60)

    # cleanup test files
    cleanup(['test_small.txt', 'test_medium.txt', 'test_large.txt', 'test_binary.bin'])

if __name__ == '__main__':
    main()
