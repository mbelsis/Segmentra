"""The Swarm lab: three managers and two workers running real services, and two clients outside the cluster.

Each node is Docker-in-Docker with its own daemon and firewall. Published ports bypass a host's normal INPUT
rules, and a default-deny policy would break the cluster, so this lab shows Segmentra handling both.
"""
import concurrent.futures
import os
import re
import subprocess
import tempfile
import time
import urllib.parse

from .common import (
    BUILD_DIR, LABEL, ROOT, Api, Checks, LabError, check_executor, connect_to_network, create_network, default_api_url, deploy, docker,
    enable_container_firewall_logs, ensure_approved_version, ensure_credential, ensure_tag, find_api_containers, find_credential,
    find_host, find_policy_set, find_tag, generate_ssh_key, has_tag, is_local, labelled, load_state, login, refuse_foreign, remove_host,
    remove_policy_set, require_docker, restore_container_firewall_logs, save_state, say, stop_sessions, versions_of, wait_for,
)

STATE_FILE = ROOT / ".demo-lab-swarm.json"
NODE_IMAGE = "segmentra-lab-swarm-node"
WEB_IMAGE = "segmentra-lab-web"
CLIENT_IMAGE = "segmentra-lab-machine"
NETWORK = "segmentra-swarm"
DEFAULT_SUBNET = "172.28.80.0/24"
TAG_NAME = "demo-lab-swarm"
CREDENTIAL_NAME = "demo-lab-swarm-credential"
POLICY_NAME = "Swarm lab policy"
CLUSTER = "demo-lab"
OVERLAY = "lab-overlay"

MANAGERS = ["swarm-m1", "swarm-m2", "swarm-m3"]
WORKERS = ["swarm-w1", "swarm-w2"]
NODES = MANAGERS + WORKERS
CLIENTS = {"swarm-client-a": 50, "swarm-client-b": 51}
FIRST_SSH_PORT = 22221  # host ports, only when the API runs outside Docker
SSH_PORTS = {name: FIRST_SSH_PORT + i for i, name in enumerate(NODES)}

SERVICES = {"web": 8080, "admin": 8081}
NEW_PORT = 8090  # a service `check` publishes while the policy is deployed
# The sample policy in one table: which client may use which published service, on every node.
ALLOWED = {("swarm-client-a", "web"), ("swarm-client-b", "admin")}
REQUESTS_PER_FLOW = 4


def node_ip(state, name):
    return f"{state['subnet'].rsplit('.', 1)[0]}.{11 + NODES.index(name)}"


def client_ip(state, name):
    return f"{state['subnet'].rsplit('.', 1)[0]}.{CLIENTS[name]}"


def in_node(name, *command, check=False, timeout=120):
    return docker("exec", name, *command, check=check, timeout=timeout)


# --- Containers and the cluster --------------------------------------------------------------------

def build_images():
    say("Building the images (the first time takes a few minutes)")
    for image in (NODE_IMAGE, WEB_IMAGE, CLIENT_IMAGE):
        refuse_foreign("image", image)
    docker("build", "--quiet", "-t", CLIENT_IMAGE, str(BUILD_DIR))
    docker("build", "--quiet", "-t", NODE_IMAGE, "-f", str(BUILD_DIR / "swarm-node.Dockerfile"), str(BUILD_DIR))
    docker("build", "--quiet", "-t", WEB_IMAGE, "-f", str(BUILD_DIR / "swarm-web.Dockerfile"), str(BUILD_DIR))


def daemon_ready(name):
    return in_node(name, "docker", "version", "--format", "{{.Server.Version}}").returncode == 0


def start_nodes(state):
    for name in NODES:
        refuse_foreign("container", name)
        if labelled("container", name):
            docker("start", name)
            continue
        publish = ["-p", f"127.0.0.1:{SSH_PORTS[name]}:{SSH_PORTS[name]}"] if state["mode"] == "published" else []
        docker(
            "run", "-d", "--name", name, "--hostname", name, "--label", f"{LABEL}=1", "--network", NETWORK, "--ip", node_ip(state, name),
            "--privileged", "--restart", "unless-stopped", "-e", "DOCKER_TLS_CERTDIR=", "-e", "DEMO_SWARM_NODE=1",
            "-e", f"SSH_PORT={SSH_PORTS[name]}", "-e", f"DEMO_MGMT_PUBLIC_KEY={state['mgmt_public_key']}", *publish, NODE_IMAGE,
        )
    say("Waiting for the Docker daemons on the nodes")
    deadline = time.time() + 120
    for name in NODES:
        while not daemon_ready(name):
            if time.time() > deadline:
                raise LabError(f"The Docker daemon on {name} did not start:\n{docker('logs', '--tail', '20', name, check=False).stderr}")
            time.sleep(2)


def start_clients(state):
    for name in CLIENTS:
        refuse_foreign("container", name)
        if labelled("container", name):
            docker("start", name)
            continue
        docker(
            "run", "-d", "--name", name, "--hostname", name, "--label", f"{LABEL}=1", "--network", NETWORK, "--ip", client_ip(state, name),
            "--restart", "unless-stopped", "--entrypoint", "sh", CLIENT_IMAGE, "-c", "exec sleep infinity",
        )


def load_web_image():
    """Copied into every node from here, so the nodes download nothing and five nodes cost one download."""
    with tempfile.TemporaryDirectory() as folder:
        archive = os.path.join(folder, "web.tar")
        docker("save", "-o", archive, WEB_IMAGE)
        for name in NODES:
            with open(archive, "rb") as data:
                done = subprocess.run(["docker", "exec", "-i", name, "docker", "load", "-q"], stdin=data, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if done.returncode != 0:
                raise LabError(f"Could not load the service image on {name}: {done.stderr.decode('utf-8', 'replace')}")


def swarm_state(name):
    return in_node(name, "docker", "info", "--format", "{{.Swarm.LocalNodeState}}").stdout


def form_swarm(state):
    first = MANAGERS[0]
    first_ip = node_ip(state, first)
    if swarm_state(first) != "active":
        in_node(first, "docker", "swarm", "init", "--advertise-addr", first_ip, check=True)
    tokens = {
        "manager": in_node(first, "docker", "swarm", "join-token", "-q", "manager", check=True).stdout,
        "worker": in_node(first, "docker", "swarm", "join-token", "-q", "worker", check=True).stdout,
    }
    for name in NODES[1:]:
        if swarm_state(name) != "active":
            token = tokens["manager" if name in MANAGERS else "worker"]
            in_node(name, "docker", "swarm", "join", "--advertise-addr", node_ip(state, name), "--token", token, f"{first_ip}:2377", check=True)


def deploy_services():
    first = MANAGERS[0]
    if in_node(first, "docker", "network", "inspect", OVERLAY).returncode != 0:
        in_node(first, "docker", "network", "create", "-d", "overlay", "--attachable", OVERLAY, check=True)
    for service, port in SERVICES.items():
        if in_node(first, "docker", "service", "inspect", service).returncode != 0:
            in_node(
                first, "docker", "service", "create", "--detach", "--name", service, "--replicas", "3", "--network", OVERLAY,
                "--hostname", "{{.Node.Hostname}}", "--no-resolve-image", "--publish", f"published={port},target=80", WEB_IMAGE, check=True,
            )
    def all_running():
        replicas = in_node(first, "docker", "service", "ls", "--format", "{{.Replicas}}").stdout.split()
        return len(replicas) >= len(SERVICES) and all(r.split("/")[0] == r.split("/")[1] for r in replicas)
    if not wait_for(all_running, 90):
        raise LabError("The services did not start:\n" + in_node(first, "docker", "service", "ls").stdout)


def cluster_health():
    """(nodes that are Ready, managers that are reachable, whether a leader exists), asked of any manager that answers."""
    for manager in MANAGERS:
        done = in_node(manager, "docker", "node", "ls", "--format", "{{.Status}} {{.ManagerStatus}}", timeout=30)
        if done.returncode == 0:
            lines = done.stdout.splitlines()
            ready = sum(1 for line in lines if line.startswith("Ready"))
            managers = sum(1 for line in lines if "Leader" in line or "Reachable" in line and "Unreachable" not in line)
            return ready, managers, any("Leader" in line for line in lines)
    return 0, 0, False


def overlay_requests(count=9):
    """Requests over the overlay network, through the service name. Replicas sit on other nodes, so this crosses VXLAN."""
    script = f"ok=0; for i in $(seq 1 {count}); do wget -q -T 3 -O /dev/null http://web && ok=$((ok+1)); done; echo $ok"
    done = in_node(MANAGERS[0], "docker", "run", "--rm", "--network", OVERLAY, "--entrypoint", "sh", WEB_IMAGE, "-c", script)
    last = done.stdout.split()[-1] if done.stdout.split() else "0"
    return int(last) if last.isdigit() else 0


# --- Inventory -------------------------------------------------------------------------------------

def ensure_hosts(api, state, tag_id):
    ids = {}
    published = state["mode"] == "published"
    for name in NODES:
        body = {
            "hostname": name, "mgmtIp": "127.0.0.1" if published else node_ip(state, name), "sshPort": SSH_PORTS[name] if published else 22,
            "firewallBackend": "iptables", "enabled": True, "tagIds": [tag_id], "swarmCluster": CLUSTER,
            "swarmRole": "manager" if name in MANAGERS else "worker", "swarmAddr": node_ip(state, name), "dockerPublishedPorts": True,
        }
        host = find_host(api, name)
        if host:
            api.request("PUT", f"/hosts/{host['id']}", body)
            ids[name] = host["id"]
        else:
            ids[name] = api.post("/hosts", body)["host"]["id"]
    return ids


def sample_rules(state):
    def rule(order, ports, source, comment, log="LOG_RATE_LIMITED"):
        return {
            "orderIndex": order, "direction": "IN", "action": "ALLOW", "protocol": "tcp", "ports": ports, "sourceType": "CIDR",
            "sourceValue": source, "logMode": log, "comment": comment, "usePolicyInterfaceScope": True,
        }

    management_ports = ",".join(["22", *(str(p) for p in SSH_PORTS.values())])
    return [
        # Keeps Segmentra's own login working when a management network is configured elsewhere.
        rule(5, management_ports, state["subnet"], "segmentra-management", "NONE"),
        rule(10, str(SERVICES["web"]), f"{client_ip(state, 'swarm-client-a')}/32", "web-client-a"),
        rule(20, str(SERVICES["admin"]), f"{client_ip(state, 'swarm-client-b')}/32", "admin-client-b"),
    ]


# --- Traffic ---------------------------------------------------------------------------------------

def attempt(client, ip, port):
    """How many of the requests a service answered, and which nodes served them."""
    script = f"for i in $(seq 1 {REQUESTS_PER_FLOW}); do curl -s --max-time 2 http://{ip}:{port}/ ; done"
    text = docker("exec", client, "sh", "-c", script, check=False, timeout=30).stdout
    served_by = re.findall(r"Hello from (\S+)", text)
    return len(served_by), set(served_by)


def probe_all(state):
    flows = [(client, node, service) for client in CLIENTS for node in NODES for service in SERVICES]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = pool.map(lambda f: attempt(f[0], node_ip(state, f[1]), SERVICES[f[2]]), flows)
        return dict(zip(flows, results))


def differences_from_policy(results):
    wrong = []
    for (client, node, service), (answered, _) in results.items():
        wanted = REQUESTS_PER_FLOW if (client, service) in ALLOWED else 0
        if answered != wanted:
            wrong.append(f"{client[-1]}>{node}:{service} {answered}/{REQUESTS_PER_FLOW}")
    return wrong


def run_traffic(state, enforced=True):
    """Prints a table. Returns the number of results that differ from the policy."""
    results = probe_all(state)
    differences = 0
    columns = [(client, service) for client in CLIENTS for service in SERVICES]
    say(f"  {'node':<12}" + "".join(f"{client[-1]}: {service:<12}" for client, service in columns))
    for node in NODES:
        cells = []
        for client, service in columns:
            answered, _ = results[(client, node, service)]
            cell = "ok" if answered == REQUESTS_PER_FLOW else "blocked" if answered == 0 else f"{answered}/{REQUESTS_PER_FLOW}"
            if enforced and answered != (REQUESTS_PER_FLOW if (client, service) in ALLOWED else 0):
                differences += 1
                cell += " (!)"
            cells.append(f"{cell:<15}")
        say(f"  {node:<12}" + "".join(cells))
    return differences


def require_state():
    state = load_state(STATE_FILE)
    if not state:
        raise LabError("The Swarm lab is not set up here. Run: python3 scripts/demo-lab.py up --lab swarm")
    return state


# --- Commands --------------------------------------------------------------------------------------

def cmd_up(args):
    require_docker()
    if not is_local(args.api_url):
        raise LabError("The Swarm lab needs Segmentra on this machine, because its Docker containers have to reach each other.")
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
    # Checked before anything is created, so a refusal leaves nothing behind.
    for name in NODES:
        host = find_host(api, name)
        if host and not has_tag(host, TAG_NAME):
            raise LabError(f"Your inventory already has a host called {name} that is not part of the lab. It was left alone; rename it first.")
    check_executor(api, state, args)

    build_images()
    if "mgmt_private_key" not in state:
        state["mgmt_public_key"], state["mgmt_private_key"] = generate_ssh_key(NODE_IMAGE)
        save_state(STATE_FILE, state)
    create_network(NETWORK, state["subnet"])
    start_nodes(state)
    start_clients(state)
    if api_containers:
        say(f"Connecting {', '.join(api_containers)} to the lab network")
        connect_to_network(api_containers, NETWORK)
    enable_container_firewall_logs(state, STATE_FILE)

    say("Forming the swarm: 3 managers, 2 workers")
    load_web_image()
    form_swarm(state)
    deploy_services()

    say("Adding the nodes to the inventory")
    tag_id = ensure_tag(api, TAG_NAME)
    ensure_credential(api, CREDENTIAL_NAME, tag_id, state["mgmt_private_key"])
    host_ids = ensure_hosts(api, state, tag_id)

    already_filtering = in_node(NODES[0], "iptables", "-S", "SEGMENTRA-FWD").returncode == 0
    say("\nBefore deploying: rules from an earlier run are active" if already_filtering else "\nBefore the policy: every client reaches every published service on every node")
    run_traffic(state, enforced=False)

    say(f"\nCreating, approving and deploying '{POLICY_NAME}'")
    version_id = ensure_approved_version(api, POLICY_NAME, "Sample Swarm policy from scripts/demo-lab.py", host_ids, lambda: sample_rules(state))
    deploy(api, version_id, host_ids)

    say("\nAfter the policy")
    time.sleep(3)
    differences = run_traffic(state)
    if differences:
        raise LabError(f"{differences} results differ from the policy, marked (!).")
    ready, managers, leader = cluster_health()
    overlay = overlay_requests()
    say(f"\nThe cluster still works: {ready} of {len(NODES)} nodes Ready, {managers} of {len(MANAGERS)} managers reachable, overlay {overlay} of 9 requests")
    if ready != len(NODES) or managers != len(MANAGERS) or not leader or overlay != 9:
        raise LabError("The policy disturbed the cluster.")

    say("\nReady. Every result matches the policy.")
    say("  client a: only the web service (8080) | client b: only the admin service (8081), on every node")
    say("\nTry this in Segmentra:")
    say("  Docker Swarm: the cluster with its managers and workers")
    say("  Inventory: Actions > Active Rules on a node, to see the cluster ports added for its peers")
    say("  Inventory: Actions > Peek at Logs on a node, then run traffic: denied published ports appear as 'published'")
    say("\n  python3 scripts/demo-lab.py traffic --lab swarm   send the traffic again")
    say("  python3 scripts/demo-lab.py check --lab swarm     test Segmentra's Swarm features against this lab")
    say("  python3 scripts/demo-lab.py down --lab swarm      remove the lab")
    say("\nFor testing only: the nodes are privileged containers.")


def cmd_traffic(args):
    require_docker()
    state = require_state()
    for name in [*NODES, *CLIENTS]:
        if docker("exec", name, "true", check=False).returncode != 0:
            raise LabError(f"{name} is not running. Run: python3 scripts/demo-lab.py up --lab swarm")
    differences = 0
    for round_number in range(args.repeat):
        if round_number:
            time.sleep(args.interval)
        if args.repeat > 1:
            say(f"Round {round_number + 1} of {args.repeat}")
        differences = run_traffic(state)
    if differences:
        say(f"\n{differences} results differ from the policy, marked (!). That is expected while a log-only test runs on a node.")
        return 1
    ready, managers, _ = cluster_health()
    say(f"\nEvery result matches the policy. {ready} of {len(NODES)} nodes Ready, {managers} of {len(MANAGERS)} managers reachable.")
    return 0


def cmd_status(args):
    require_docker()
    state = load_state(STATE_FILE)
    say(f"Set up from this folder: {'yes' if state else 'no'}")
    if state:
        say(f"Network: {NETWORK} ({state['subnet']}), reached by {'the API container' if state['mode'] == 'connected' else 'ports published on 127.0.0.1'}")
    for name in [*NODES, *CLIENTS]:
        running = docker("inspect", "--format", "{{.State.Status}}", name, check=False)
        ip = "" if not state else node_ip(state, name) if name in NODES else client_ip(state, name)
        say(f"  {name}: {running.stdout if running.returncode == 0 else 'not created'} {ip}")
    if state and docker("exec", MANAGERS[0], "true", check=False).returncode == 0:
        say("\n" + in_node(MANAGERS[0], "docker", "node", "ls", "--format", "  {{.Hostname}}  {{.Status}}  {{.ManagerStatus}}").stdout)
        say(in_node(MANAGERS[0], "docker", "service", "ls", "--format", "  {{.Name}}  {{.Replicas}}  {{.Ports}}").stdout)
    return 0


def cmd_check(args):
    """Segmentra's Swarm features against the real cluster. Changes the lab for a while, then restores it."""
    require_docker()
    state = require_state()
    api = Api(args.api_url or state.get("api_url") or default_api_url())
    login(api, args)
    policy = find_policy_set(api, POLICY_NAME)
    hosts = {name: find_host(api, name) for name in NODES}
    if not policy or not all(hosts.values()):
        raise LabError("The Swarm lab is not in this Segmentra. Run: python3 scripts/demo-lab.py up --lab swarm")
    host_ids = {name: host["id"] for name, host in hosts.items()}
    usable = [v for v in versions_of(api, policy["id"]) if v["status"] in ("APPROVED", "DEPLOYED")]
    if not usable:
        raise LabError(f"'{POLICY_NAME}' has no approved version. Run: python3 scripts/demo-lab.py up --lab swarm")
    version_id = usable[0]["id"]
    first, worker = MANAGERS[0], WORKERS[0]
    checks = Checks()
    check = checks.check

    def compliance(name):
        return api.get(f"/compliance/hosts/{host_ids[name]}").get("status")

    def healthy():
        ready, managers, leader = cluster_health()
        return ready == len(NODES) and managers == len(MANAGERS) and leader

    def rules(name, chain):
        return in_node(name, "iptables", "-S", chain).stdout

    def update_hosts(body_for):
        for name in NODES:
            api.request("PUT", f"/hosts/{host_ids[name]}", body_for(name))

    say("Traffic and the cluster")
    wrong = differences_from_policy(probe_all(state))
    check("every client reaches only what the policy allows, on every node", not wrong, str(wrong) if wrong else "")
    _, served = attempt("swarm-client-a", node_ip(state, WORKERS[1]), SERVICES["web"])
    check("the routing mesh still spreads requests between replicas", len(served) > 1, f"{WORKERS[1]} was served by {sorted(served)}")
    check("all nodes are Ready and all managers reachable", healthy(), str(cluster_health()))
    overlay = overlay_requests()
    check("the overlay network works across nodes", overlay == 9, f"{overlay} of 9")

    say("\nThe Docker Swarm page")
    swarm = next((s for s in api.get("/hosts/swarms/overview").get("swarms", []) if s["name"] == CLUSTER), None)
    nodes = (swarm or {}).get("nodes", [])
    check("it lists the cluster with all five nodes", len(nodes) == len(NODES), f"{len(nodes)} nodes")
    check("it shows three managers and two workers", sum(n.get("swarm_role") == "manager" for n in nodes) == 3 and sum(n.get("swarm_role") == "worker" for n in nodes) == 2)

    say("\nGenerated rules")
    manager_rules, worker_rules = rules(first, "SEGMENTRA-IN"), rules(worker, "SEGMENTRA-IN")
    peers = [node_ip(state, n) for n in NODES if n != first]
    check("a manager accepts the manager port from all four peers", all(re.search(rf"-s {re.escape(ip)}/32 .*--dport 2377", manager_rules) for ip in peers))
    check("a worker does not open the manager port", "2377" not in worker_rules)
    check("cluster ports allow only the peers, not the clients", not any(client_ip(state, c) in line for c in CLIENTS for line in manager_rules.splitlines() if "swarm" in line.lower()))
    check("Docker's own chain sends published traffic to Segmentra first", rules(first, "DOCKER-USER").splitlines()[1:2] == ["-A DOCKER-USER -j SEGMENTRA-FWD"])
    check("all nodes are compliant", all(compliance(n) == "compliant" for n in NODES))

    say("\nA service published after the deployment")
    in_node(
        first, "docker", "service", "create", "--detach", "--name", "later", "--replicas", "1", "--no-resolve-image",
        "--publish", f"published={NEW_PORT},target=80", WEB_IMAGE, check=True,
    )
    wait_for(lambda: in_node(first, "docker", "service", "ls", "--filter", "name=later", "--format", "{{.Replicas}}").stdout == "1/1", 60)
    time.sleep(10)
    answered = attempt("swarm-client-a", node_ip(state, worker), NEW_PORT)[0]
    check("it is blocked until a policy allows it, with no redeployment", answered == 0, f"{answered} of {REQUESTS_PER_FLOW}")
    answered = attempt("swarm-client-a", node_ip(state, worker), SERVICES["web"])[0]
    check("the allowed service keeps working after Docker reorders its rules", answered == REQUESTS_PER_FLOW, f"{answered} of {REQUESTS_PER_FLOW}")
    in_node(first, "docker", "service", "rm", "later", check=True)
    time.sleep(5)

    say("\nPeek at Logs on a node")
    probe_all(state)

    def entries(name):
        return api.get(f"/compliance/hosts/{host_ids[name]}/firewall-logs?limit=500").get("entries", [])

    def published_denials(name):
        return [e for e in entries(name) if e.get("action") == "DENY" and (e.get("rule") or "").startswith("published")]

    denied = wait_for(lambda: published_denials(worker))
    check("denied published ports are in the log", denied, f"{len(denied or [])} lines")
    clients = {client_ip(state, c) for c in CLIENTS}
    check("they show the client that was refused", bool(denied) and all(e.get("sourceIp") in clients for e in denied), str(sorted({e.get('sourceIp') for e in denied or []})))

    def published_allowed(name):
        return [e for e in entries(name) if e.get("action") == "ALLOW" and (e.get("rule") or "").startswith("web-client")]

    allowed = wait_for(lambda: published_allowed(worker))
    check("allowed published traffic is in the log under its rule's name", allowed, f"{len(allowed or [])} lines")

    say("\nDrift: someone removes the jump from Docker's chain")
    in_node(worker, "iptables", "-D", "DOCKER-USER", "-j", "SEGMENTRA-FWD", check=True)
    status = compliance(worker)
    check("Segmentra reports that node as drifted", status != "compliant", str(status))
    check("the other nodes stay compliant", compliance(first) == "compliant")
    deploy(api, version_id, host_ids)
    time.sleep(3)
    check("deploying again restores it", compliance(worker) == "compliant" and not differences_from_policy(probe_all(state)))

    say("\nPolicy Impact Analysis on a worker (log-only)")
    session = api.post("/policy-test/start", {"policyVersionId": version_id, "hostId": host_ids[worker], "durationMinutes": 5})["session"]["id"]
    try:
        time.sleep(20)
        check("the cluster stays healthy during a log-only test", healthy(), str(cluster_health()))
        overlay = overlay_requests()
        check("the overlay keeps working during a log-only test", overlay == 9, f"{overlay} of 9")
        probe_all(state)
        time.sleep(2)
    finally:
        stopped = api.request("POST", f"/policy-test/sessions/{session}/stop", {}, ok=(200, 400, 404, 409, 500))[1]
    check("the test collected log lines", stopped.get("entryCount", 0) > 0, f"{stopped.get('entryCount')} lines")
    wrong = wait_for(lambda: not differences_from_policy(probe_all(state)), 15)
    check("the enforced rules are back after the test", wrong and compliance(worker) == "compliant")

    say("\nWithout published-port enforcement (control)")
    update_hosts(lambda name: {"dockerPublishedPorts": False})
    deploy(api, version_id, host_ids)
    time.sleep(3)
    answered = attempt("swarm-client-b", node_ip(state, worker), SERVICES["web"])[0]
    check("a client the policy does not allow gets through, because INPUT rules cannot stop it", answered == REQUESTS_PER_FLOW, f"{answered} of {REQUESTS_PER_FLOW}")
    update_hosts(lambda name: {"dockerPublishedPorts": True})
    deploy(api, version_id, host_ids)
    time.sleep(3)
    answered = attempt("swarm-client-b", node_ip(state, worker), SERVICES["web"])[0]
    check("with enforcement back on, it is blocked again", answered == 0, f"{answered} of {REQUESTS_PER_FLOW}")

    say("\nWithout the Swarm profile (control)")
    update_hosts(lambda name: {"swarmCluster": None})
    deploy(api, version_id, host_ids)
    time.sleep(25)
    overlay = overlay_requests()
    check("default deny breaks the overlay, though no rule mentions it", overlay < 9, f"{overlay} of 9")
    update_hosts(lambda name: {"swarmCluster": CLUSTER, "swarmRole": "manager" if name in MANAGERS else "worker", "swarmAddr": node_ip(state, name)})
    deploy(api, version_id, host_ids)
    recovered = wait_for(lambda: overlay_requests() == 9 and healthy(), 90)
    check("with the profile back, the overlay and the cluster recover", recovered, str(cluster_health()))

    say("\nLosing a manager")
    lost = MANAGERS[2]
    docker("stop", "--time", "5", lost)
    reachable = wait_for(lambda: cluster_health()[1] == 2 and cluster_health()[2], 60)
    check("two of three managers keep the cluster manageable", reachable, str(cluster_health()))
    answered = attempt("swarm-client-a", node_ip(state, worker), SERVICES["web"])[0]
    check("the allowed service keeps answering", answered == REQUESTS_PER_FLOW, f"{answered} of {REQUESTS_PER_FLOW}")
    docker("start", lost)
    wait_for(lambda: daemon_ready(lost), 90)
    rejoined = wait_for(healthy, 120)
    check("the restarted manager rejoins", rejoined, str(cluster_health()))
    status = compliance(lost)
    check("Segmentra reports it as not compliant: a restarted container has lost its rules", status != "compliant", str(status))
    deploy(api, version_id, host_ids)
    time.sleep(3)
    wrong = differences_from_policy(probe_all(state))
    check("deploying again restores every node", compliance(lost) == "compliant" and not wrong, str(wrong) if wrong else "")
    recovered = wait_for(lambda: overlay_requests() == 9 and healthy(), 60)
    check("the cluster is healthy at the end", recovered, str(cluster_health()))

    say(f"\n{checks.count - len(checks.failed)} of {checks.count} checks passed")
    if checks.failed:
        raise LabError("Failed: " + "; ".join(checks.failed))
    return 0


def clean_up_inventory(api):
    kept = []
    hosts = [h for h in (find_host(api, name) for name in NODES) if h and has_tag(h, TAG_NAME)]
    for host in hosts:
        stop_sessions(api, host)
    if not remove_policy_set(api, POLICY_NAME):
        kept.append(f"policy '{POLICY_NAME}' (archived)")
    for host in hosts:
        if not remove_host(api, host):
            # A disabled host is no longer a peer, but the Swarm page would still list the cluster.
            api.request("PUT", f"/hosts/{host['id']}", {"swarmCluster": None})
            kept.append(f"host {host['hostname']} (disabled)")
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
        say(f"  Warning: Segmentra was not cleaned up ({error}). Remove the swarm-* hosts and '{POLICY_NAME}' by hand if they remain.")

    say("Removing the nodes and the network")
    for name in [*NODES, *CLIENTS]:
        if labelled("container", name):
            docker("rm", "-f", "-v", name, check=False)
    for name in state.get("api_containers") or []:
        docker("network", "disconnect", NETWORK, name, check=False)
    docker("network", "rm", NETWORK, check=False)
    restore_container_firewall_logs(state, STATE_FILE)
    if args.remove_images:
        for image in (NODE_IMAGE, WEB_IMAGE):
            if labelled("image", image):
                docker("rmi", image, check=False)
    if STATE_FILE.exists():
        STATE_FILE.unlink()

    say("Done.")
    if kept:
        say(f"Segmentra keeps deployment history, so these remain: {', '.join(kept)}. Running `up` again reuses them.")
    return 0
