import hashlib
import json
from web3 import Web3

def compute_threat_hash(event):
    """Stable hash for blockchain dedup"""
    key_fields = {
        "path": event.get("path", ""),
        "params": event.get("params", {}),
        "cmdline": event.get("cmdline", ""),
        "technique": event.get("technique", "")
    }
    hash_str = json.dumps(key_fields, sort_keys=True)
    return hashlib.sha256(hash_str.encode()).hexdigest()

def query_blockchain_reputation(threat_hash, blockchain_data_str):
    """
    Check if hash is in ledger
    blockchain_data_str: JSON with ledger entries
    """
    try:
        ledger = json.loads(blockchain_data_str)
        for entry in ledger.get("entries", []):
            if entry.get("threat_hash") == threat_hash:
                return {
                    "found": True,
                    "anomaly_score": entry.get("anomaly_score"),
                    "verdict": entry.get("verdict"),
                    "cached": True
                }
    except:
        pass
    
    return {
        "found": False,
        "cached": False,
        "verdict": "UNKNOWN"
    }

def commit_to_blockchain(threat_hash, anomaly_score, verdict):
    """Simulate ledger write"""
    return {
        "tx_hash": f"0x{hashlib.sha256(threat_hash.encode()).hexdigest()[:16]}",
        "status": "CONFIRMED",
        "threat_hash": threat_hash,
        "anomaly_score": anomaly_score,
        "verdict": verdict,
        "timestamp": datetime.now().isoformat()
    }

# Main logic
threat_hash = compute_threat_hash(event)
blockchain_status = query_blockchain_reputation(threat_hash, blockchain_ledger)

if not blockchain_status["found"]:
    commit_result = commit_to_blockchain(threat_hash, anomaly_score, "MALICIOUS")
    blockchain_status["committed"] = True

return blockchain_status
