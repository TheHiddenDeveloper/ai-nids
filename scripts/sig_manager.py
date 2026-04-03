#!/usr/bin/env python3
"""
Signature Manager CLI
---------------------
Manage the NIDS signature rule database without editing YAML by hand.

Commands:
    list                    List all rules (with status and tags)
    list --tag dos          Filter by tag
    list --enabled-only     Only show enabled rules
    show <RULE_ID>          Show full details of one rule
    test <RULE_ID>          Test a rule against a simulated flow
    enable  <RULE_ID>       Enable a disabled rule
    disable <RULE_ID>       Disable a rule without deleting it
    stats                   Show rule counts by severity and tag

Usage examples:
    python scripts/sig_manager.py list
    python scripts/sig_manager.py list --tag c2
    python scripts/sig_manager.py show SYN_FLOOD_001
    python scripts/sig_manager.py test PORT_SCAN_001
    python scripts/sig_manager.py enable DNS_EXFIL_001
    python scripts/sig_manager.py disable BAD_PORT_VNC
    python scripts/sig_manager.py stats
"""

import sys
import argparse
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from signatures.loader import load_rules, Rule

RULES_PATH = Path("signatures/rules.yaml")

# ── Terminal colours ──────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

SEV_COLOR = {"high": RED, "medium": YELLOW, "low": CYAN}

def colored(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"

def sev_badge(severity: str) -> str:
    icons = {"high": "[HIGH]  ", "medium": "[MED]   ", "low": "[LOW]   "}
    return colored(icons.get(severity, "[?]     "), SEV_COLOR.get(severity, ""))


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_yaml_raw() -> dict:
    with open(RULES_PATH) as f:
        return yaml.safe_load(f)

def save_yaml_raw(data: dict):
    with open(RULES_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

def find_rule_index(data: dict, rule_id: str) -> int:
    """Return index of rule in data['rules'] list, or -1."""
    for i, r in enumerate(data.get("rules", [])):
        if r.get("id") == rule_id:
            return i
    return -1

def set_rule_enabled(rule_id: str, enabled: bool):
    data = load_yaml_raw()
    idx = find_rule_index(data, rule_id)
    if idx == -1:
        print(colored(f"Rule '{rule_id}' not found.", RED))
        sys.exit(1)
    data["rules"][idx]["enabled"] = enabled
    save_yaml_raw(data)
    state = colored("enabled", GREEN) if enabled else colored("disabled", DIM)
    print(f"Rule {colored(rule_id, BOLD)} → {state}")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_list(args):
    rules = load_rules(str(RULES_PATH))

    if args.tag:
        rules = [r for r in rules if args.tag in r.tags]
    if args.enabled_only:
        rules = [r for r in rules if r.enabled]

    if not rules:
        print("No rules match your filter.")
        return

    w_id   = max(len(r.id) for r in rules) + 2
    w_name = max(len(r.name) for r in rules) + 2

    header = f"{'ID':<{w_id}} {'STATUS':<10} {'SEV':<8} {'NAME':<{w_name}} TAGS"
    print(colored(header, BOLD))
    print("─" * (w_id + w_name + 40))

    for r in rules:
        status = colored("ON ", GREEN) if r.enabled else colored("OFF", DIM)
        sev    = colored(f"{r.severity:<6}", SEV_COLOR.get(r.severity, ""))
        tags   = ", ".join(r.tags)
        print(f"{r.id:<{w_id}} {status}        {sev}   {r.name:<{w_name}} {colored(tags, DIM)}")

    print()
    enabled = sum(1 for r in rules if r.enabled)
    print(f"Total: {len(rules)}  |  Enabled: {colored(str(enabled), GREEN)}  |  Disabled: {colored(str(len(rules)-enabled), DIM)}")


def cmd_show(args):
    rules = load_rules(str(RULES_PATH))
    rule  = next((r for r in rules if r.id == args.rule_id), None)

    if not rule:
        print(colored(f"Rule '{args.rule_id}' not found.", RED))
        sys.exit(1)

    status = colored("ENABLED", GREEN) if rule.enabled else colored("DISABLED", DIM)
    sev    = colored(rule.severity.upper(), SEV_COLOR.get(rule.severity, ""))

    print()
    print(colored(f"  {rule.id}", BOLD))
    print(f"  Name        : {rule.name}")
    print(f"  Status      : {status}")
    print(f"  Severity    : {sev}")
    print(f"  Tags        : {', '.join(rule.tags)}")
    print(f"  Description : {rule.description.strip()}")
    print()
    print(colored("  Conditions (ALL must match):", BOLD))
    for i, c in enumerate(rule.conditions, 1):
        print(f"    {i}. {colored(c.field, CYAN)} {c.op} {colored(str(c.value), YELLOW)}")
    print()


def cmd_test(args):
    """Run a rule against a built-in test flow and report whether it fires."""
    rules = load_rules(str(RULES_PATH))
    rule  = next((r for r in rules if r.id == args.rule_id), None)

    if not rule:
        print(colored(f"Rule '{args.rule_id}' not found.", RED))
        sys.exit(1)

    # Build a flow that satisfies all numeric conditions
    test_flow = {
        "dst_port":           80,
        "syn_flag_count":     100,
        "ack_flag_count":     0,
        "fin_flag_count":     0,
        "rst_flag_count":     50,
        "psh_flag_count":     0,
        "urg_flag_count":     0,
        "packet_count":       2,
        "duration":           0.1,
        "src_bytes":          9_000_000,
        "dst_bytes":          100,
        "flow_bytes_per_sec": 15_000_000,
        "flow_packets_per_sec": 600,
        "avg_packet_len":     50,
        "_dst_port":          rule.conditions[0].value
                              if any(c.field == "_dst_port" for c in rule.conditions)
                              else 80,
    }
    # Override with exact condition values so the rule triggers
    for c in rule.conditions:
        if c.op in ("eq", "in"):
            test_flow[c.field] = c.value if c.op == "eq" else c.value[0]
        elif c.op in ("gt", "gte"):
            test_flow[c.field] = float(c.value) + 1
        elif c.op in ("lt", "lte"):
            test_flow[c.field] = float(c.value) - 1

    fired = rule.matches(test_flow)
    print()
    print(colored(f"  Testing rule: {rule.id} — {rule.name}", BOLD))
    print(f"  Test flow   : {test_flow}")
    print()
    if fired:
        print(colored("  RESULT: FIRED  — rule conditions satisfied", GREEN))
    else:
        print(colored("  RESULT: DID NOT FIRE — review conditions manually", RED))
    print()


def cmd_enable(args):
    set_rule_enabled(args.rule_id, enabled=True)


def cmd_disable(args):
    set_rule_enabled(args.rule_id, enabled=False)


def cmd_stats(args):
    rules = load_rules(str(RULES_PATH))

    by_severity: defaultdict = defaultdict(int)
    by_tag:      defaultdict = defaultdict(int)
    enabled = disabled = 0

    for r in rules:
        by_severity[r.severity] += 1
        for t in r.tags:
            by_tag[t] += 1
        if r.enabled:
            enabled += 1
        else:
            disabled += 1

    print()
    print(colored("  Signature Database Stats", BOLD))
    print(f"  Rules file : {RULES_PATH}")
    print(f"  Total rules: {len(rules)}")
    print(f"  Enabled    : {colored(str(enabled), GREEN)}")
    print(f"  Disabled   : {colored(str(disabled), DIM)}")
    print()

    print(colored("  By severity:", BOLD))
    for sev in ("high", "medium", "low"):
        bar = "█" * by_severity.get(sev, 0)
        print(f"    {colored(f'{sev:<8}', SEV_COLOR.get(sev,''))} {bar} {by_severity.get(sev,0)}")

    print()
    print(colored("  By tag:", BOLD))
    for tag, count in sorted(by_tag.items(), key=lambda x: -x[1]):
        bar = "█" * count
        print(f"    {tag:<15} {bar} {count}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI-NIDS signature rule manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = sub.add_parser("list", help="List all rules")
    p_list.add_argument("--tag",          help="Filter by tag (e.g. dos, c2, scan)")
    p_list.add_argument("--enabled-only", action="store_true", help="Only show enabled rules")

    # show
    p_show = sub.add_parser("show", help="Show full rule details")
    p_show.add_argument("rule_id", help="Rule ID (e.g. SYN_FLOOD_001)")

    # test
    p_test = sub.add_parser("test", help="Test a rule against a simulated flow")
    p_test.add_argument("rule_id", help="Rule ID to test")

    # enable / disable
    p_en = sub.add_parser("enable",  help="Enable a rule")
    p_en.add_argument("rule_id")
    p_dis = sub.add_parser("disable", help="Disable a rule")
    p_dis.add_argument("rule_id")

    # stats
    sub.add_parser("stats", help="Show rule statistics")

    args = parser.parse_args()

    dispatch = {
        "list":    cmd_list,
        "show":    cmd_show,
        "test":    cmd_test,
        "enable":  cmd_enable,
        "disable": cmd_disable,
        "stats":   cmd_stats,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
