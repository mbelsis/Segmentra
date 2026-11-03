"""The base lab: three machines (test-a, test-b, test-c), a sample policy and a sample SIEM."""
import collections
import re
import time
import urllib.parse

from .common import (
    BUILD_DIR, LABEL, ROOT, Api, LabError, check_executor, connect_to_network, create_network, default_api_url, deploy, docker,
    enable_container_firewall_logs, ensure_approved_version, ensure_credential, ensure_tag, find_api_containers, find_credential,
    find_host, generate_ssh_key, has_tag, is_local, labelled, load_state, login, refuse_foreign, remove_host, remove_policy_set,
    require_docker, restore_container_firewall_logs, save_state, say, stop_sessions,
)

STATE_FILE = ROOT / ".demo-lab.json"
NETWORK = "segmentra-demo-lab"
DEFAULT_SUBNET = "172.28.77.0/24"
TAG_NAME = "demo-lab"
CREDENTIAL_NAME = "demo-lab-credential"
POLICY_NAME = "Demo lab policy"
MACHINES = ["test-a", "test-b", "test-c"]
FIRST_SSH_PORT = 22201  # host ports, only when the API runs outside Docker

# A stand-in SIEM: a syslog receiver, registered in Segmentra as one integration per protocol.
SYSLOG_NAME = "test-syslog"
SYSLOG_HOST_PORT = 15514  # on 127.0.0.1, only when the API runs outside Docker
SIEM_PROTOCOLS = ["tcp", "udp"]
SIEM_MESSAGE = re.compile(r'^<\d+>1 (\S+) segmentra segmentra-audit - - \[audit@segmentra action="([^"]*)" actor="([^"]*)" entityType="([^"]*)" entityId="([^"]*)"')

ACTIONS = ["ping", "ssh", "telnet", "curl"]
# Which machine may do what, enforced on every machine. This is the sample policy in one table.
ALLOWED = {
    "ping": {"test-a"},
    "ssh": {"test-a"},
    "telnet": {"test-c"},
    "curl": {"test-a", "test-b"},
}


def lab_ips(subnet):
    prefix = subnet.rsplit(".", 1)[0]
    return {name: f"{prefix}.{11 + i}" for i, name in enumerate(MACHINES)}


def syslog_ip(subnet):
    return subnet.rsplit(".", 1)[0] + ".20"


def build_images():
    say("Building the images test-a, test-b and test-c (the first time takes a minute or two)")
    names = [*MACHINES, SYSLOG_NAME]
    for name in names:
        refuse_foreign("image", name)
    docker("build", "--quiet", "-t", names[0], str(BUILD_DIR))
    for name in names[1:]:
        docker("tag", names[0], name)


def start_machines(state):
    ips = lab_ips(state["subnet"])
    for i, name in enumerate(MACHINES):
        refuse_foreign("container", name)
        if labelled("container", name):
            docker("start", name)
            continue
        publish = ["-p", f"127.0.0.1:{FIRST_SSH_PORT + i}:22"] if state["mode"] == "published" else []
        docker(
            "run", "-d", "--name", name, "--hostname", name, "--label", f"{LABEL}=1",
            "--network", NETWORK, "--ip", ips[name], "--privileged", "--restart", "unless-stopped",
            "-e", f"DEMO_MGMT_PUBLIC_KEY={state['mgmt_public_key']}", *publish, name,
        )
    say("Waiting for the machines to start")
    deadline = time.time() + 60
    for name in MACHINES:
        while docker("exec", name, "pgrep", "-x", "sshd", check=False).returncode != 0:
            if time.time() > deadline:
                logs = docker("logs", "--tail", "20", name, check=False)
                raise LabError(f"{name} did not start:\n{logs.stdout}\n{logs.stderr}")
            time.sleep(1)


def start_syslog_receiver(state):
    refuse_foreign("container", SYSLOG_NAME)
    if labelled("container", SYSLOG_NAME):
        docker("start", SYSLOG_NAME)
    else:
        publish = []
        if state["mode"] == "published":
            publish = ["-p", f"127.0.0.1:{SYSLOG_HOST_PORT}:514/tcp", "-p", f"127.0.0.1:{SYSLOG_HOST_PORT}:514/udp"]
        docker(
            "run", "-d", "--name", SYSLOG_NAME, "--hostname", SYSLOG_NAME, "--label", f"{LABEL}=1",
            "--network", NETWORK, "--ip", syslog_ip(state["subnet"]), "--restart", "unless-stopped",
            "--entrypoint", "/syslog-receiver.sh", *publish, SYSLOG_NAME,
        )
    deadline = time.time() + 30
    while docker("exec", SYSLOG_NAME, "pgrep", "-x", "rsyslogd", check=False).returncode != 0:
        if time.time() > deadline:
            raise LabError(f"{SYSLOG_NAME} did not start:\n{docker('logs', '--tail', '20', SYSLOG_NAME, check=False).stderr}")
        time.sleep(1)


def ensure_hosts(api, state, tag_id):
    ips = lab_ips(state["subnet"])
    ids = {}
    for i, name in enumerate(MACHINES):
        published = state["mode"] == "published"
        body = {
            "hostname": name, "mgmtIp": "127.0.0.1" if published else ips[name],
            "sshPort": FIRST_SSH_PORT + i if published else 22,
            "firewallBackend": "iptables", "enabled": True, "tagIds": [tag_id],
        }
        host = find_host(api, name)
        if host and not has_tag(host, TAG_NAME):
            raise LabError(f"Your inventory already has a host called {name} that is not part of the demo lab. It was left alone; rename it first.")
        if host:
            api.request("PUT", f"/hosts/{host['id']}", body)
            ids[name] = host["id"]
        else:
            ids[name] = api.post("/hosts", body)["host"]["id"]
    return ids


def sample_rules(state):
    ips = lab_ips(state["subnet"])
    a, b, c = (f"{ips[m]}/32" for m in MACHINES)

    def rule(order, action, protocol, ports, source, comment, log="LOG_RATE_LIMITED"):
        body = {
            "orderIndex": order, "direction": "IN", "action": action, "protocol": protocol, "sourceType": "CIDR",
            "sourceValue": source, "logMode": log, "comment": comment, "usePolicyInterfaceScope": True,
        }
        return {**body, "ports": ports} if ports else body

    # Comments stay short: they become log prefixes, which iptables limits to 29 bytes.
    return [
        # Keeps Segmentra's own login working when a management network is configured elsewhere.
        rule(5, "ALLOW", "tcp", "22", state["subnet"], "segmentra-management", "NONE"),
        rule(10, "ALLOW", "icmp", None, a, "ping-a"),
        rule(20, "ALLOW", "tcp", "2222", a, "ssh-a"),
        rule(30, "ALLOW", "tcp", "80", a, "web-a"),
        rule(31, "ALLOW", "tcp", "80", b, "web-b"),
        rule(40, "ALLOW", "tcp", "23", c, "telnet-c"),
        rule(50, "DENY", "tcp", "23", b, "no-telnet"),
    ]


def siem_integrations(api):
    return {i["name"]: i for i in api.get("/integrations").get("integrations", []) if i["name"].startswith("demo-lab-siem-")}


def ensure_siem(api, state):
    """One SIEM integration per protocol, both pointing at the receiver."""
    published = state["mode"] == "published"
    host, port = ("127.0.0.1", SYSLOG_HOST_PORT) if published else (syslog_ip(state["subnet"]), 514)
    existing = siem_integrations(api)
    ids = {}
    for protocol in SIEM_PROTOCOLS:
        name = f"demo-lab-siem-{protocol}"
        body = {
            "type": "siem", "provider": "syslog", "name": name, "description": "Sample SIEM from scripts/demo-lab.py", "enabled": True,
            "config": {"host": host, "port": port, "protocol": protocol},
        }
        if name in existing:
            api.request("PUT", f"/integrations/{existing[name]['id']}", body)
            ids[protocol] = existing[name]["id"]
        else:
            ids[protocol] = api.post("/integrations", body)["integration"]["id"]
    return ids


def read_siem(protocol):
    """(time, action, actor, entity type, entity id) of each valid message, and how many lines were not valid."""
    text = docker("exec", SYSLOG_NAME, "cat", f"/var/log/siem/{protocol}.log", check=False).stdout
    messages, invalid = [], 0
    for line in text.splitlines():
        match = SIEM_MESSAGE.match(line)
        if match:
            messages.append(match.groups())
        elif line.strip():
            invalid += 1
    return messages, invalid


def wait_for_siem(action_prefix, seconds=30):
    """Waits until the receiver has the action on every protocol. Returns the protocols it never arrived on."""
    deadline = time.time() + seconds
    while True:
        missing = [p for p in SIEM_PROTOCOLS if not any(m[1].startswith(action_prefix) for m in read_siem(p)[0])]
        if not missing or time.time() > deadline:
            return missing
        time.sleep(1)


def attempt(action, source, target, target_ip):
    """Real clients inside the source machine. True when the service answered."""
    commands = {
        "ping": f"ping -c 1 -W 2 {target_ip}",
        "ssh": f"sshpass -p demo ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3 demo@{target_ip} hostname | grep -qx {target}",
        "telnet": f"sleep 2 | timeout 4 telnet {target_ip} 2>/dev/null | grep -q 'login:'",
        "curl": f"curl -s --max-time 3 http://{target_ip}/ | grep -q 'Hello from {target}'",
    }
    return docker("exec", source, "sh", "-c", commands[action], check=False, timeout=15).returncode == 0


def run_traffic(state, enforced=True):
    """Prints a table. Returns the number of results that differ from the policy."""
    ips = lab_ips(state["subnet"])
    say(f"  {'from':<8}{'to':<8}" + "".join(f"{a:<14}" for a in ACTIONS))
    differences = 0
    for source in MACHINES:
        for target in MACHINES:
            if source == target:
                continue
            cells = []
            for action in ACTIONS:
                reached = attempt(action, source, target, ips[target])
                cell = "ok" if reached else "blocked"
                if enforced and reached != (source in ALLOWED[action]):
                    differences += 1
                    cell += " (!)"
                cells.append(f"{cell:<14}")
            say(f"  {source:<8}{target:<8}" + "".join(cells))
    return differences


def require_state():
    state = load_state(STATE_FILE)
    if not state:
        raise LabError("The demo lab is not set up here. Run: python3 scripts/demo-lab.py up")
    return state


# --- Commands --------------------------------------------------------------------------------------

def cmd_up(args):
    require_docker()
    if not is_local(args.api_url):
        raise LabError("The demo lab needs Segmentra on this machine, because its Docker containers have to reach each other.")
    api = Api(args.api_url)
    say(f"Logging in to Segmentra at {args.api_url}")
    login(api, args)

    state = load_state(STATE_FILE) or {"subnet": args.subnet or DEFAULT_SUBNET}
    port = urllib.parse.urlparse(args.api_url).port or 80
    api_containers = find_api_containers(port)
    state["mode"] = "connected" if api_containers else "published"
    state["api_containers"] = api_containers
    state["runner"] = any("ansible-runner" in n for n in api_containers)
    state["api_url"] = args.api_url
    save_state(STATE_FILE, state)
    # Checked before anything is created in the inventory, so a refusal leaves nothing behind.
    for name in MACHINES:
        host = find_host(api, name)
        if host and not has_tag(host, TAG_NAME):
            raise LabError(f"Your inventory already has a host called {name} that is not part of the demo lab. It was left alone; rename it first.")
    check_executor(api, state, args)

    build_images()
    if "mgmt_private_key" not in state:
        state["mgmt_public_key"], state["mgmt_private_key"] = generate_ssh_key(MACHINES[0])
        save_state(STATE_FILE, state)
    create_network(NETWORK, state["subnet"])
    start_machines(state)
    if api_containers:
        say(f"Connecting {', '.join(api_containers)} to the lab network")
        connect_to_network(api_containers, NETWORK)
    enable_container_firewall_logs(state, STATE_FILE)

    say("Adding the machines to the inventory")
    tag_id = ensure_tag(api, TAG_NAME)
    ensure_credential(api, CREDENTIAL_NAME, tag_id, state["mgmt_private_key"])
    host_ids = ensure_hosts(api, state, tag_id)

    say("Connecting the sample SIEM")
    start_syslog_receiver(state)
    siem_ids = ensure_siem(api, state)

    say("\nBefore the policy: everything is open")
    run_traffic(state, enforced=False)

    say(f"\nCreating, approving and deploying '{POLICY_NAME}'")
    version_id = ensure_approved_version(api, POLICY_NAME, "Sample policy from scripts/demo-lab.py", host_ids, lambda: sample_rules(state))
    deploy(api, version_id, host_ids)

    say("\nAfter the policy")
    differences = run_traffic(state)
    if differences:
        raise LabError(f"{differences} results differ from the policy, marked (!).")

    for integration_id in siem_ids.values():
        api.post(f"/integrations/{integration_id}/test")
    missing = wait_for_siem("INTEGRATION_TEST") + wait_for_siem("DEPLOYMENT_")
    if missing:
        raise LabError(f"The sample SIEM did not receive the events over: {', '.join(sorted(set(missing)))}. Check the API's log for [SIEM] lines.")

    say("\nThe sample SIEM received the audit events over TCP and UDP.")
    say("\nReady. Every result matches the policy.")
    say("  ping and ssh (port 2222): only from test-a | telnet: only from test-c | curl: from test-a and test-b")
    say("\nTry this in Segmentra:")
    say("  Inventory: Actions > Peek at Logs on a machine, to see accepted and denied traffic")
    say("  Policy Impact Analysis: start a test, then run the traffic command below")
    say("\n  python3 scripts/demo-lab.py traffic      send the sample traffic again")
    say("  python3 scripts/demo-lab.py siem         see what the sample SIEM received")
    say("  python3 scripts/demo-lab.py down         remove the lab")
    say("\nFor testing only: these are privileged containers with a known user password.")


def cmd_traffic(args):
    require_docker()
    state = require_state()
    for name in MACHINES:
        if docker("exec", name, "true", check=False).returncode != 0:
            raise LabError(f"{name} is not running. Run: python3 scripts/demo-lab.py up")
    differences = 0
    for round_number in range(args.repeat):
        if round_number:
            time.sleep(args.interval)
        if args.repeat > 1:
            say(f"Round {round_number + 1} of {args.repeat}")
        differences = run_traffic(state)
    if differences:
        say(f"\n{differences} results differ from the policy, marked (!). That is expected while a log-only test runs, because nothing is blocked then.")
        return 1
    say("\nEvery result matches the policy.")
    return 0


def cmd_siem(args):
    require_docker()
    require_state()
    if docker("exec", SYSLOG_NAME, "true", check=False).returncode != 0:
        raise LabError(f"{SYSLOG_NAME} is not running. Run: python3 scripts/demo-lab.py up")
    say("The sample SIEM receives Segmentra's Audit Log. Firewall log lines are not forwarded.\n")
    newest = []
    for protocol in SIEM_PROTOCOLS:
        messages, invalid = read_siem(protocol)
        say(f"{protocol.upper()}: {len(messages)} messages" + (f", {invalid} not in the expected format" if invalid else ""))
        if protocol == SIEM_PROTOCOLS[0]:
            newest = messages
    if args.by_action:
        say("\nBy action (TCP):")
        for action, count in collections.Counter(m[1] for m in newest).most_common():
            say(f"  {count:>5}  {action}")
    say(f"\nNewest {min(args.last, len(newest))} (TCP):")
    for when, action, actor, entity_type, entity_id in newest[-args.last:]:
        say(f"  {when[:19]}  {action:<28}{actor:<20}{entity_type}:{entity_id[:8]}")
    return 0


def cmd_status(args):
    require_docker()
    state = load_state(STATE_FILE)
    say(f"Set up from this folder: {'yes' if state else 'no'}")
    if state:
        say(f"Network: {NETWORK} ({state['subnet']}), reached by {'the API container' if state['mode'] == 'connected' else 'ports published on 127.0.0.1'}")
    ips = lab_ips(state["subnet"]) if state else {}
    if state:
        ips[SYSLOG_NAME] = syslog_ip(state["subnet"])
    for name in [*MACHINES, SYSLOG_NAME]:
        running = docker("inspect", "--format", "{{.State.Status}}", name, check=False)
        say(f"  {name}: {running.stdout if running.returncode == 0 else 'not created'} {ips.get(name, '')}")
    return 0


def clean_up_inventory(api):
    kept = []
    hosts = [h for h in (find_host(api, name) for name in MACHINES) if h and has_tag(h, TAG_NAME)]
    for host in hosts:
        stop_sessions(api, host)
    if not remove_policy_set(api, POLICY_NAME):
        kept.append(f"policy '{POLICY_NAME}' (archived)")
    for host in hosts:
        if not remove_host(api, host):
            kept.append(f"host {host['hostname']} (disabled)")
    for integration in siem_integrations(api).values():
        api.request("DELETE", f"/integrations/{integration['id']}", ok=(200, 204, 400, 404, 409))
    credential = find_credential(api, CREDENTIAL_NAME)
    if credential:
        api.request("DELETE", f"/ssh-credentials/{credential['id']}", ok=(200, 204, 400, 404, 409))
    for tag in api.get("/tags").get("tags", []):
        if tag["name"] == TAG_NAME and not any("host " in k for k in kept):
            api.request("DELETE", f"/tags/{tag['id']}", ok=(200, 204, 400, 404, 409))
    return kept


def cmd_down(args):
    require_docker()
    state = load_state(STATE_FILE) or {}
    api = Api(args.api_url or state.get("api_url") or default_api_url())
    kept = []
    try:
        login(api, args)
        say("Removing the lab from Segmentra")
        kept = clean_up_inventory(api)
    except LabError as error:
        say(f"  Warning: Segmentra was not cleaned up ({error}). Remove the hosts and '{POLICY_NAME}' by hand if they remain.")

    say("Removing the machines and the network")
    for name in [*MACHINES, SYSLOG_NAME]:
        if labelled("container", name):
            docker("rm", "-f", "-v", name, check=False)
    for name in state.get("api_containers") or []:
        docker("network", "disconnect", NETWORK, name, check=False)
    docker("network", "rm", NETWORK, check=False)
    restore_container_firewall_logs(state, STATE_FILE)
    if args.remove_images:
        for name in [*MACHINES, SYSLOG_NAME]:
            if labelled("image", name):
                docker("rmi", name, check=False)
    if STATE_FILE.exists():
        STATE_FILE.unlink()

    say("Done.")
    if kept:
        say(f"Segmentra keeps deployment history, so these remain: {', '.join(kept)}. Running `up` again reuses them.")
    return 0
