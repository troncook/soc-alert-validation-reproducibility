"""Standard-library verification of public bytes and aggregate arithmetic."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT/'evidence/20260905'


def read(path): return json.loads(path.read_text(encoding='utf-8'))
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    snapshot = read(ROOT/'source_snapshot.json')
    for relative, expected in snapshot['files'].items():
        assert sha(ROOT/relative) == expected, relative
    manifest = read(EVIDENCE/'manifest.json')
    assert manifest['status'] == 'complete' and manifest['source_unchanged_during_run']
    for relative, expected in manifest['source_hashes'].items():
        assert sha(ROOT/relative.replace('\\','/')) == expected, relative
    available = 0
    for relative, expected in manifest['output_hashes'].items():
        path = EVIDENCE/relative.replace('\\','/')
        if path.exists():
            assert sha(path) == expected, relative
            available += 1
    results = read(EVIDENCE/'results.json')
    assert len(results) == 6
    policies = 0
    for result in results:
        assert not any(result['split_checks']['overlap_checks'].values())
        assert result['smt_disagreements'] == 0
        lock = EVIDENCE/result['condition']/'selection_lock.json'
        assert sha(lock) == result['selection_lock_sha256']
        assert read(lock) == result['selection']
        for m in result['policies'].values():
            assert m['baseline_tp']-m['retained_tp'] == m['tp_removed']
            assert m['baseline_fp']-m['retained_fp'] == m['fp_removed']
            assert m['validated_fn'] == m['baseline_fn']+m['tp_removed']
            assert m['malicious']+m['benign'] == m['test_rows']
            assert m['recall_delta'] == (-m['tp_removed']/m['malicious'] if m['malicious'] else None)
            policies += 1
    print(json.dumps({'status':'passed','snapshot_files':len(snapshot['files']),'available_original_output_hashes':available,'conditions':len(results),'policy_count_reconciliations':policies,'scope':'Published bytes and aggregate arithmetic only; full reproduction regenerates private row-level evidence.'},indent=2))


if __name__ == '__main__': main()
