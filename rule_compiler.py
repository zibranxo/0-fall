import json

def compile_waf_rule(rule_spec):
    """Convert LLM rule to live WAF config"""
    waf_config = {
        "rule_id": rule_spec.get("name", "auto_rule"),
        "action": rule_spec.get("action", "BLOCK"),
        "condition": rule_spec.get("condition", ""),
        "description": rule_spec.get("description", ""),
        "format": "modsecurity"
    }
    
    # Generate ModSecurity snippet
    modsec_rule = f"""
    SecRule ARGS|HEADERS {{"{waf_config['condition']}"}}  \\
        "id:{hash(waf_config['rule_id']) % 10000}," \\
        "phase:2," \\
        "action:{waf_config['action']},log,msg:'WireFall+ {waf_config['rule_id']}'"
    """.strip()
    
    return {
        "waf_rule_id": waf_config["rule_id"],
        "modsecurity_snippet": modsec_rule,
        "applied": True,
        "config_reload": "reload_nginx"
    }

def compile_edr_rule(rule_spec):
    """Convert LLM rule to YARA-like EDR config"""
    edr_config = {
        "rule_name": rule_spec.get("name", "auto_edr_rule"),
        "action": rule_spec.get("action", "KILL_PROCESS"),
        "pattern": rule_spec.get("process_pattern", ""),
        "description": rule_spec.get("description", "")
    }
    
    yara_rule = f"""
    rule {edr_config['rule_name']} {{
        strings:
            $pattern = "{edr_config['pattern']}"
        condition:
            $pattern
    }}
    """.strip()
    
    return {
        "edr_rule_id": edr_config["rule_name"],
        "yara_snippet": yara_rule,
        "applied": True,
        "agent_signal": "monitor_process_tree"
    }

# Compile both
waf_result = compile_waf_rule(waf_rule_spec)
edr_result = compile_edr_rule(edr_rule_spec)

return {
    "waf": waf_result,
    "edr": edr_result,
    "status": "RULES_APPLIED",
    "timestamp": datetime.now().isoformat()
}
