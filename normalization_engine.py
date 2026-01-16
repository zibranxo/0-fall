import json
from datetime import datetime

def normalize_logs(web_logs_str, edr_logs_str):
    """
    Unifies web + EDR logs into common schema
    """
    normalized_events = []
    
    # Parse web logs
    try:
        web_logs = json.loads(web_logs_str)
        for log in web_logs:
            event = {
                "id": f"web_{log.get('request_id')}",
                "source": "WAF",
                "timestamp": log.get("timestamp", datetime.now().isoformat()),
                "path": log.get("path", ""),
                "method": log.get("method", "GET"),
                "params": log.get("params", {}),
                "headers": log.get("headers", {}),
                "body": log.get("body", ""),
                "client_ip": log.get("client_ip", ""),
                "status_code": log.get("status", 200),
                "type": "WEB_REQUEST"
            }
            normalized_events.append(event)
    except:
        pass
    
    # Parse EDR logs
    try:
        edr_logs = json.loads(edr_logs_str)
        for log in edr_logs:
            event = {
                "id": f"edr_{log.get('event_id')}",
                "source": "EDR",
                "timestamp": log.get("timestamp", datetime.now().isoformat()),
                "pid": log.get("pid"),
                "cmdline": log.get("cmdline", ""),
                "parent_pid": log.get("parent_pid"),
                "user": log.get("user", ""),
                "syscall": log.get("syscall", ""),
                "type": "PROCESS_EVENT"
            }
            normalized_events.append(event)
    except:
        pass
    
    return {
        "total_events": len(normalized_events),
        "events": normalized_events,
        "schema_version": "1.0"
    }

# Call this
result = normalize_logs(web_logs, edr_logs)
return result
