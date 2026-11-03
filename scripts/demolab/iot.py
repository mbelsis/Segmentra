"""The IoT lab: a gateway between an IT and an OT network, IT clients, and simulated devices behind it.

The devices cannot run a firewall, so the gateway filters what is routed to them: FORWARD rules plus a
default deny for every device assigned to it. All traffic between the networks really crosses the gateway.
"""
import concurrent.futures
import time
import urllib.parse

from .common import (
    BUILD_DIR, LABEL, ROOT, Api, LabError, check_executor, connect_to_network, create_network, default_api_url, deploy, docker,
    enable_container_firewall_logs, ensure_approved_version, ensure_credential, ensure_tag, find_api_containers, find_credential,
    find_host, find_policy_set, find_tag, generate_ssh_key, has_tag, is_local, labelled, load_state, login, refuse_foreign, remove_host,
    remove_policy_set, require_docker, restore_container_firewall_logs, save_state, say, stop_sessions, versions_of,
)

STATE_FILE = ROOT / ".demo-lab-iot.json"
IMAGE = "segmentra-lab-machine"
IT_NETWORK = "segmentra-iot-it"
OT_NETWORK = "segmentra-iot-ot"
DEFAULT_IT_SUBNET = "172.28.78.0/24"
DEFAULT_OT_SUBNET = "172.28.79.0/24"
TAG_NAME = "demo-lab-iot"
GATEWAY_TAG = "iot-gateway"  # Segmentra's system tag for gateways
CREDENTIAL_NAME = "demo-lab-iot-credential"
POLICY_NAME = "IoT lab policy"
ASSET_NOTE = "Simulated device from scripts/demo-lab.py"
GATEWAY = "iot-gw"
GATEWAY_SSH_PORT = 22211  # host port, only when the API runs outside Docker
GATEWAY_HOST_PART = 2

# name: (last part of its IT address, what it answers)
CLIENTS = {
    "iot-hmi": (50, []),
    "iot-eng": (51, []),
    "iot-office": (52, ["http"]),
}
# name: (last part of its OT address, what it answers, registered in Segmentra as)
DEVICES = {
    "iot-plc": (11, ["modbus", "s7"], {"assetType": "plc", "model": "PLC", "criticality": "critical"}),
    "iot-rtu": (12, ["dnp3", "modbus"], {"assetType": "other", "model": "RTU", "criticality": "high"}),
    "iot-sensor": (13, ["mqtt"], {"assetType": "sensor", "model": "Sensor", "criticality": "medium"}),
    "iot-camera": (14, ["rtsp", "http"], {"assetType": "camera", "model": "Camera", "criticality": "medium"}),
    # Not registered on purpose: discovery should find it, and nothing protects it until someone does.
    "iot-printer": (15, ["jetdirect"], None),
}
REGISTERED = [name for name, device in DEVICES.items() if device[2]]
PORTS = {"modbus": "502", "s7": "102", "dnp3": "20000", "mqtt": "1883", "rtsp": "554", "http": "80", "jetdirect": "9100"}

# The sample policy in one table: (client, device, service). Everything else to a registered device is denied.
ALLOWED = {
    ("iot-hmi", "iot-plc", "modbus"),
    ("iot-hmi", "iot-rtu", "dnp3"),
    ("iot-hmi", "iot-sensor", "mqtt"),
    ("iot-hmi", "iot-camera", "rtsp"),
    ("iot-eng", "iot-plc", "s7"),
    ("iot-eng", "iot-sensor", "mqtt"),
    ("iot-office", "iot-camera", "http"),
}


def expected_flows():
    """(source, target, service, should it work), in the order they are shown."""
    flows = []
    for device, (_, services, registered) in DEVICES.items():
        for service in services:
            for client in CLIENTS:
                flows.append((client, device, service, not registered or (client, device, service) in ALLOWED))
    flows.append(("iot-hmi", "iot-plc", "ping", False))  # ICMP is not allowed to a protected device
    flows.append(("iot-plc", "iot-office", "http", False))  # the explicit rule: devices may not call into IT
    flows.append(("iot-plc", "iot-rtu", "modbus", True))  # same network, so it never reaches the gateway
    return flows


def address(subnet, host_part):
    return f"{subnet.rsplit('.', 1)[0]}.{host_part}"


def machine_ip(state, name):
    if name in CLIENTS:
        return address(state["subnet"], CLIENTS[name][0])
    return address(state["ot_subnet"], DEVICES[name][0])


# --- Containers ------------------------------------------------------------------------------------

def start_gateway(state):
    refuse_foreign("container", GATEWAY)
    if labelled("container", GATEWAY):
        docker("start", GATEWAY)
    else:
        publish = ["-p", f"127.0.0.1:{GATEWAY_SSH_PORT}:22"] if state["mode"] == "published" else []
        # Connected to both networks before it starts, so it knows all its addresses from the beginning.
        docker(
            "create", "--name", GATEWAY, "--hostname", GATEWAY, "--label", f"{LABEL}=1",
            "--network", IT_NETWORK, "--ip", address(state["subnet"], GATEWAY_HOST_PART), "--privileged", "--restart", "unless-stopped",
            "--sysctl", "net.ipv4.ip_forward=1", "-e", "DEMO_GATEWAY=1",
            "-e", f"DEMO_MGMT_PUBLIC_KEY={state['mgmt_public_key']}", *publish, IMAGE,
        )
        docker("network", "connect", "--ip", address(state["ot_subnet"], GATEWAY_HOST_PART), OT_NETWORK, GATEWAY)
        docker("start", GATEWAY)


def start_simulated(name, network, ip, route, services):
    """Clients and devices: no SSH, no firewall of their own, just a route through the gateway."""
    refuse_foreign("container", name)
    if labelled("container", name):
        docker("start", name)
        return
    script = f"ip route replace {route} && exec python3 /iot-device.py serve {' '.join(services)}"
    docker(
        "run", "-d", "--name", name, "--hostname", name, "--label", f"{LABEL}=1", "--network", network, "--ip", ip,
        "--cap-add", "NET_ADMIN", "--restart", "unless-stopped", "--entrypoint", "sh", IMAGE, "-c", script,
    )


def start_machines(state):
    start_gateway(state)
    gateway_it = address(state["subnet"], GATEWAY_HOST_PART)
    gateway_ot = address(state["ot_subnet"], GATEWAY_HOST_PART)
    for name, (_, services) in CLIENTS.items():
        start_simulated(name, IT_NETWORK, machine_ip(state, name), f"{state['ot_subnet']} via {gateway_it}", services)
    for name, (_, services, _) in DEVICES.items():
        start_simulated(name, OT_NETWORK, machine_ip(state, name), f"default via {gateway_ot}", services)
    say("Waiting for the machines to start")
    deadline = time.time() + 60
    while docker("exec", GATEWAY, "pgrep", "-x", "sshd", check=False).returncode != 0:
        if time.time() > deadline:
            logs = docker("logs", "--tail", "20", GATEWAY, check=False)
            raise LabError(f"{GATEWAY} did not start:\n{logs.stdout}\n{logs.stderr}")
        time.sleep(1)
    for name in [*CLIENTS, *DEVICES]:
        while docker("inspect", "--format", "{{.State.Running}}", name, check=False).stdout != "true":
            if time.time() > deadline:
                raise LabError(f"{name} did not start:\n{docker('logs', '--tail', '20', name, check=False).stderr}")
            time.sleep(1)
    time.sleep(1)  # the simulated services need a moment to open their ports


def all_machines():
    return [GATEWAY, *CLIENTS, *DEVICES]


# --- Inventory -------------------------------------------------------------------------------------

def ensure_gateway(api, state, tag_ids):
    published = state["mode"] == "published"
    body = {
        "hostname": GATEWAY, "mgmtIp": "127.0.0.1" if published else address(state["subnet"], GATEWAY_HOST_PART),
        "sshPort": GATEWAY_SSH_PORT if published else 22, "firewallBackend": "iptables", "enabled": True, "tagIds": tag_ids,
    }
    host = find_host(api, GATEWAY)
    if host:
        api.request("PUT", f"/hosts/{host['id']}", body)
        return host["id"]
    return api.post("/hosts", body)["host"]["id"]


def find_assets(api):
    return {a["name"]: a for a in api.get("/iot-assets").get("assets", []) if a["name"] in REGISTERED}


def ensure_assets(api, state, gateway_id):
    existing = find_assets(api)
    ids = {}
    for name in REGISTERED:
        body = {
            "name": name, "description": ASSET_NOTE, "vendor": "Simulated", "ipAddress": machine_ip(state, name),
            "zone": "lab-line-1", "enabled": True, **DEVICES[name][2],
        }
        if name in existing:
            ids[name] = existing[name]["id"]
            api.request("PUT", f"/iot-assets/{ids[name]}", body)
            api.post(f"/iot-assets/{ids[name]}/gateways", {"gatewayIds": [gateway_id]})
        else:
            ids[name] = api.post("/iot-assets", {**body, "gatewayIds": [gateway_id]})["asset"]["id"]
    return ids


def sample_rules(state, asset_ids):
    it_subnet, ot_subnet = state["subnet"], state["ot_subnet"]

    def forward(order, action, protocol, ports, source, destination_type, destination, comment, log="LOG_RATE_LIMITED"):
        body = {
            "orderIndex": order, "direction": "FORWARD", "action": action, "protocol": protocol, "sourceType": "CIDR",
            "sourceValue": source, "destinationType": destination_type, "destinationValue": destination, "logMode": log,
            "comment": comment, "usePolicyInterfaceScope": True,
        }
        return {**body, "ports": ports} if ports else body

    def allow(order, client, device, service):
        comment = f"{client[4:]}-{device[4:]}-{service}"
        return forward(order, "ALLOW", "tcp", PORTS[service], f"{machine_ip(state, client)}/32", "IOT_ASSET", asset_ids[device], comment)

    # Same order on purpose: the allows, then the two explicit denies. Comments become log prefixes, limited to 29 bytes.
    rules = [
        # Keeps Segmentra's own login working when a management network is configured elsewhere.
        {
            "orderIndex": 5, "direction": "IN", "action": "ALLOW", "protocol": "tcp", "ports": "22", "sourceType": "CIDR",
            "sourceValue": it_subnet, "logMode": "NONE", "comment": "segmentra-management", "usePolicyInterfaceScope": True,
        },
    ]
    rules += [allow(10 + 10 * i, *flow) for i, flow in enumerate(sorted(ALLOWED))]
    rules.append(forward(100, "DENY", "tcp", PORTS["modbus"], it_subnet, "IOT_ASSET", asset_ids["iot-rtu"], "no-modbus-rtu"))
    rules.append(forward(110, "DENY", "any", None, ot_subnet, "CIDR", it_subnet, "ot-no-it"))
    return rules


# --- Traffic ---------------------------------------------------------------------------------------

def attempt(state, source, target, service):
    """A real request from inside the source machine. True when the device answered."""
    ip = machine_ip(state, target)
    if service == "ping":
        command = ["ping", "-c", "1", "-W", "2", ip]
    else:
        command = ["python3", "/iot-device.py", "probe", service, ip]
    return docker("exec", source, *command, check=False, timeout=15).returncode == 0


def probe_all(state):
    """Every flow at once, because a blocked one has to time out."""
    flows = expected_flows()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = pool.map(lambda flow: attempt(state, flow[0], flow[1], flow[2]), flows)
        return list(zip(flows, results))


def run_traffic(state, enforced=True):
    """Prints a table. Returns the number of results that differ from the policy."""
    results = {(s, t, svc): (reached, should) for (s, t, svc, should), reached in probe_all(state)}
    differences = 0

    def cell(key):
        nonlocal differences
        reached, should = results[key]
        text = "ok" if reached else "blocked"
        if enforced and reached != should:
            differences += 1
            text += " (!)"
        return text

    columns = [name[4:] for name in CLIENTS]
    say(f"  {'device':<10}{'service':<12}" + "".join(f"{c:<14}" for c in columns))
    for device, (_, services, _) in DEVICES.items():
        for service in services:
            say(f"  {device[4:]:<10}{service:<12}" + "".join(f"{cell((client, device, service)):<14}" for client in CLIENTS))
    say("")
    say(f"  hmi to plc, ping (ICMP):                       {cell(('iot-hmi', 'iot-plc', 'ping'))}")
    say(f"  plc to office, http (a device calling IT):     {cell(('iot-plc', 'iot-office', 'http'))}")
    say(f"  plc to rtu, modbus (same network, no gateway): {cell(('iot-plc', 'iot-rtu', 'modbus'))}")
    return differences


def require_state():
    state = load_state(STATE_FILE)
    if not state:
        raise LabError("The IoT lab is not set up here. Run: python3 scripts/demo-lab.py up --lab iot")
    return state


# --- Commands --------------------------------------------------------------------------------------

def cmd_up(args):
    require_docker()
    if not is_local(args.api_url):
        raise LabError("The IoT lab needs Segmentra on this machine, because its Docker containers have to reach each other.")
    api = Api(args.api_url)
    say(f"Logging in to Segmentra at {args.api_url}")
    login(api, args)

    state = load_state(STATE_FILE) or {"subnet": args.subnet or DEFAULT_IT_SUBNET, "ot_subnet": args.ot_subnet or DEFAULT_OT_SUBNET}
    port = urllib.parse.urlparse(args.api_url).port or 80
    api_containers = find_api_containers(port)
    state["mode"] = "connected" if api_containers else "published"
    state["api_containers"] = api_containers
    state["runner"] = any("ansible-runner" in n for n in api_containers)
    state["api_url"] = args.api_url
    save_state(STATE_FILE, state)
    # Checked before anything is created, so a refusal leaves nothing behind.
    host = find_host(api, GATEWAY)
    if host and not has_tag(host, TAG_NAME):
        raise LabError(f"Your inventory already has a host called {GATEWAY} that is not part of the lab. It was left alone; rename it first.")
    for name, asset in find_assets(api).items():
        if asset.get("description") != ASSET_NOTE:
            raise LabError(f"Your inventory already has an IoT asset called {name} that is not part of the lab. It was left alone; rename it first.")
    system_tag = find_tag(api, GATEWAY_TAG)
    if not system_tag:
        raise LabError(f"Segmentra has no {GATEWAY_TAG} tag. Is its database up to date?")
    check_executor(api, state, args)

    say("Building the lab image (the first time takes a minute or two)")
    refuse_foreign("image", IMAGE)
    docker("build", "--quiet", "-t", IMAGE, str(BUILD_DIR))
    if "mgmt_private_key" not in state:
        state["mgmt_public_key"], state["mgmt_private_key"] = generate_ssh_key(IMAGE)
        save_state(STATE_FILE, state)
    create_network(IT_NETWORK, state["subnet"])
    create_network(OT_NETWORK, state["ot_subnet"])
    start_machines(state)
    if api_containers:
        say(f"Connecting {', '.join(api_containers)} to the IT network")
        connect_to_network(api_containers, IT_NETWORK)
    enable_container_firewall_logs(state, STATE_FILE)

    say("Adding the gateway and the devices to the inventory")
    tag_id = ensure_tag(api, TAG_NAME)
    ensure_credential(api, CREDENTIAL_NAME, tag_id, state["mgmt_private_key"])
    gateway_id = ensure_gateway(api, state, [tag_id, system_tag["id"]])
    asset_ids = ensure_assets(api, state, gateway_id)

    already_filtering = docker("exec", GATEWAY, "iptables", "-S", "SEGMENTRA-FWD", check=False).returncode == 0
    say("\nBefore deploying: rules from an earlier run are active" if already_filtering else "\nBefore the policy: the gateway routes everything")
    run_traffic(state, enforced=False)

    say(f"\nCreating, approving and deploying '{POLICY_NAME}'")
    version_id = ensure_approved_version(api, POLICY_NAME, "Sample IoT/OT policy from scripts/demo-lab.py", {GATEWAY: gateway_id}, lambda: sample_rules(state, asset_ids))
    deploy(api, version_id, {GATEWAY: gateway_id})

    say("\nAfter the policy")
    differences = run_traffic(state)
    if differences:
        raise LabError(f"{differences} results differ from the policy, marked (!).")

    say("\nReady. Every result matches the policy.")
    say("  printer is open to everyone because it is not registered: nothing protects a device until it is.")
    say("  plc to rtu never reaches the gateway, so no gateway can filter it.")
    say("\nTry this in Segmentra:")
    say("  OT/IoT > Coverage: which devices are protected, and what can reach them")
    say("  OT/IoT > Discovery: run it on iot-gw and find the unregistered printer")
    say("  Inventory: Actions > Peek at Logs on iot-gw, to see allowed and denied traffic to the devices")
    say("\n  python3 scripts/demo-lab.py traffic --lab iot   send the traffic again")
    say("  python3 scripts/demo-lab.py check --lab iot     test Segmentra's features against this lab")
    say("  python3 scripts/demo-lab.py down --lab iot      remove the lab")
    say("\nFor testing only: the gateway is a privileged container, and the devices are small simulators.")


def cmd_traffic(args):
    require_docker()
    state = require_state()
    for name in all_machines():
        if docker("exec", name, "true", check=False).returncode != 0:
            raise LabError(f"{name} is not running. Run: python3 scripts/demo-lab.py up --lab iot")
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


def cmd_status(args):
    require_docker()
    state = load_state(STATE_FILE)
    say(f"Set up from this folder: {'yes' if state else 'no'}")
    if state:
        say(f"Networks: {IT_NETWORK} ({state['subnet']}), {OT_NETWORK} ({state['ot_subnet']})")
        say(f"Gateway reached by {'the API container' if state['mode'] == 'connected' else f'port {GATEWAY_SSH_PORT} on 127.0.0.1'}")
    for name in all_machines():
        running = docker("inspect", "--format", "{{.State.Status}}", name, check=False)
        ip = ""
        if state and name == GATEWAY:
            ip = f"{address(state['subnet'], GATEWAY_HOST_PART)} and {address(state['ot_subnet'], GATEWAY_HOST_PART)}"
        elif state:
            ip = machine_ip(state, name)
        say(f"  {name}: {running.stdout if running.returncode == 0 else 'not created'} {ip}")
    return 0


class Checks:
    def __init__(self):
        self.failed = []
        self.count = 0

    def check(self, label, passed, detail=""):
        self.count += 1
        if not passed:
            self.failed.append(label)
        say(f"  {'PASS' if passed else 'FAIL'}  {label}" + (f"  ({detail})" if detail else ""))
        return passed


def wait_for(read, seconds=20):
    """Polls until read() is truthy, because logs and statuses arrive a moment later."""
    deadline = time.time() + seconds
    while True:
        value = read()
        if value or time.time() > deadline:
            return value
        time.sleep(2)


def cmd_check(args):
    """Segmentra's IoT features against the real gateway. Changes the lab for a while, then restores it."""
    require_docker()
    state = require_state()
    api = Api(args.api_url or state.get("api_url") or default_api_url())
    login(api, args)
    gateway = find_host(api, GATEWAY)
    policy = find_policy_set(api, POLICY_NAME)
    if not gateway or not policy:
        raise LabError("The IoT lab is not in this Segmentra. Run: python3 scripts/demo-lab.py up --lab iot")
    gateway_id = gateway["id"]
    deployed = [v for v in versions_of(api, policy["id"]) if v["status"] in ("APPROVED", "DEPLOYED")]
    if not deployed:
        raise LabError(f"'{POLICY_NAME}' has no approved version. Run: python3 scripts/demo-lab.py up --lab iot")
    version_id = deployed[0]["id"]
    assets = find_assets(api)
    targets = {GATEWAY: gateway_id}
    checks = Checks()
    check = checks.check

    def traffic_differences():
        return [flow[:3] for flow, reached in probe_all(state) if reached != flow[3]]

    def compliance():
        return api.get(f"/compliance/hosts/{gateway_id}").get("status")

    def coverage():
        return {a["name"]: a for a in api.get("/iot-assets/coverage").get("assets", [])}

    say("Traffic")
    differences = traffic_differences()
    check("every flow matches the policy", not differences, str(differences) if differences else "")
    rules_text = docker("exec", GATEWAY, "iptables", "-S").stdout
    check("the FORWARD chain jumps to Segmentra's rules exactly once", rules_text.count("-A FORWARD -j SEGMENTRA-FWD") == 1)

    say("\nInventory")
    readiness = api.post(f"/host-readiness/hosts/{gateway_id}/check")
    check("the readiness check finds the gateway usable", not readiness.get("errors"), str(readiness.get("errors") or readiness.get("iptablesVersion")))
    check("the gateway is compliant after the deployment", compliance() == "compliant")

    say("\nCoverage")
    covered = coverage()
    check("all registered devices are protected", all(covered.get(n, {}).get("state") == "PROTECTED" for n in REGISTERED), str({n: covered.get(n, {}).get("state") for n in REGISTERED}))
    check("the printer is not listed as protected, because it is not registered", "iot-printer" not in covered)
    plc = covered.get("iot-plc", {})
    check("the plc shows Modbus from the HMI as allowed and flags it as cleartext", any(r.get("action") == "ALLOW" and r.get("ports") == "502" for r in plc.get("rules", [])) and "Modbus/TCP" in plc.get("cleartextAllowed", []))
    rtu = covered.get("iot-rtu", {})
    check("the rtu shows the explicit Modbus deny", any(r.get("action") == "DENY" and r.get("ports") == "502" for r in rtu.get("rules", [])))

    say("\nDiscovery from the gateway's neighbour table")
    found = {d["ip"]: d for d in api.post("/iot-assets/discover", {"gatewayId": gateway_id}).get("devices", [])}
    check("the registered devices are recognised", all(found.get(machine_ip(state, n), {}).get("status") == "known" for n in REGISTERED), str({n: found.get(machine_ip(state, n), {}).get("status") for n in REGISTERED}))
    check("the unregistered printer is found as a new device", found.get(machine_ip(state, "iot-printer"), {}).get("status") == "candidate")

    say("\nPeek at Logs on the gateway")
    probe_all(state)

    def log_entries():
        return api.get(f"/compliance/hosts/{gateway_id}/firewall-logs?limit=500").get("entries", [])

    def forwarded(entries, action=None, rule=None, destination=None):
        return [
            e for e in entries if e.get("direction") == "FORWARD"
            and (action is None or e.get("action") == action)
            and (rule is None or (e.get("rule") or "").startswith(rule))
            and (destination is None or e.get("destinationIp") == destination)
        ]

    plc_ip = machine_ip(state, "iot-plc")
    entries = wait_for(lambda: (lambda e: e if forwarded(e, "ALLOW") and forwarded(e, "DENY") else None)(log_entries())) or log_entries()
    check("allowed traffic through the gateway is in the log", forwarded(entries, "ALLOW", destination=plc_ip), f"{len(forwarded(entries, 'ALLOW'))} lines")
    check("the default deny for a protected device is in the log", forwarded(entries, "DENY", destination=plc_ip), f"{len(forwarded(entries, 'DENY'))} lines")
    check("the explicit Modbus deny is in the log under its own name", forwarded(entries, "DENY", rule="no-modbus"), str(sorted({e.get('rule') for e in forwarded(entries, 'DENY')})))
    check("a device calling into IT is in the log as denied", forwarded(entries, "DENY", rule="ot-no-it"))

    say("\nDrift: someone removes a rule by hand")
    removal = (
        f"iptables -S SEGMENTRA-FWD | grep -- '-d {plc_ip}/32 -p tcp' | grep -- '--dport 502' | grep -- '-j RETURN' | sed 's/^-A/iptables -D/' | sh"
    )
    docker("exec", GATEWAY, "sh", "-c", removal)
    check("Segmentra reports the gateway as drifted", compliance() == "drifted", str(compliance()))
    check("the HMI really lost its Modbus access", not attempt(state, "iot-hmi", "iot-plc", "modbus"))
    deploy(api, version_id, targets)
    check("deploying again restores the rule and the access", attempt(state, "iot-hmi", "iot-plc", "modbus") and compliance() == "compliant")

    say("\nPolicy Impact Analysis on the gateway (log-only)")
    session = api.post("/policy-test/start", {"policyVersionId": version_id, "hostId": gateway_id, "durationMinutes": 5})["session"]["id"]
    try:
        check("nothing is blocked during a log-only test", attempt(state, "iot-office", "iot-plc", "s7"))
        probe_all(state)
        time.sleep(2)
        stopped = api.post(f"/policy-test/sessions/{session}/stop")
    except LabError:
        api.request("POST", f"/policy-test/sessions/{session}/stop", {}, ok=(200, 400, 404, 409, 500))
        raise
    check("the test collected log lines", stopped.get("entryCount", 0) > 0, f"{stopped.get('entryCount')} lines")
    summary = api.post(f"/policy-test/sessions/{session}/analyze")["analysis"]["summary"]
    check("the analysis sees the routed flows", summary.get("forwarded", 0) > 0, f"{summary.get('forwarded')} of {summary.get('totalFlows')}")
    check("flows the policy allows are matched", summary.get("matched", 0) > 0, f"{summary.get('matched')} matched")
    check("flows the policy would block are reported", summary.get("unexpectedAllows", 0) + summary.get("unexpectedBlocks", 0) > 0, f"{summary.get('unexpectedAllows')} default deny, {summary.get('unexpectedBlocks')} explicit deny")
    differences = wait_for(lambda: not traffic_differences(), 10)
    check("the enforced rules are back after the test", differences)

    say("\nTaking a device off the gateway")
    camera = assets["iot-camera"]["id"]
    api.request("DELETE", f"/iot-assets/{camera}/gateways/{gateway_id}")
    check("coverage shows the camera without a gateway", coverage().get("iot-camera", {}).get("state") == "NO_GATEWAY")
    check("the gateway still blocks it until it is redeployed", not attempt(state, "iot-office", "iot-camera", "rtsp"))
    deploy(api, version_id, targets)
    check("after the deployment the camera is open, because nothing protects it", attempt(state, "iot-office", "iot-camera", "rtsp"))
    check("the other devices stay protected", not attempt(state, "iot-office", "iot-plc", "modbus"))
    api.post(f"/iot-assets/{camera}/gateways", {"gatewayIds": [gateway_id]})
    deploy(api, version_id, targets)
    differences = traffic_differences()
    check("assigned and deployed again, every flow matches the policy", not differences, str(differences) if differences else "")
    check("the camera is protected again", coverage().get("iot-camera", {}).get("state") == "PROTECTED")

    say(f"\n{checks.count - len(checks.failed)} of {checks.count} checks passed")
    if checks.failed:
        raise LabError("Failed: " + "; ".join(checks.failed))
    return 0


def clean_up_inventory(api):
    kept = []
    host = find_host(api, GATEWAY)
    if host and not has_tag(host, TAG_NAME):
        host = None
    if host:
        stop_sessions(api, host)
    if not remove_policy_set(api, POLICY_NAME):
        kept.append(f"policy '{POLICY_NAME}' (archived)")
    # Rules of archived versions no longer count as using an asset, so the assets can go.
    for asset in find_assets(api).values():
        if asset.get("description") == ASSET_NOTE:
            status, _ = api.request("DELETE", f"/iot-assets/{asset['id']}", ok=(200, 204, 400, 404, 409))
            if status not in (200, 204):
                kept.append(f"IoT asset {asset['name']}")
    if host and not remove_host(api, host):
        kept.append(f"host {GATEWAY} (disabled)")
    credential = find_credential(api, CREDENTIAL_NAME)
    if credential:
        api.request("DELETE", f"/ssh-credentials/{credential['id']}", ok=(200, 204, 400, 404, 409))
    tag = find_tag(api, TAG_NAME)
    if tag and not any("host " in k for k in kept):
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
        say(f"  Warning: Segmentra was not cleaned up ({error}). Remove {GATEWAY}, the iot-* devices and '{POLICY_NAME}' by hand if they remain.")

    say("Removing the machines and the networks")
    for name in all_machines():
        if labelled("container", name):
            docker("rm", "-f", "-v", name, check=False)
    for name in state.get("api_containers") or []:
        docker("network", "disconnect", IT_NETWORK, name, check=False)
    docker("network", "rm", IT_NETWORK, check=False)
    docker("network", "rm", OT_NETWORK, check=False)
    restore_container_firewall_logs(state, STATE_FILE)
    if args.remove_images and labelled("image", IMAGE):
        docker("rmi", IMAGE, check=False)
    if STATE_FILE.exists():
        STATE_FILE.unlink()

    say("Done.")
    if kept:
        say(f"Segmentra keeps deployment history, so these remain: {', '.join(kept)}. Running `up` again reuses them.")
    return 0
