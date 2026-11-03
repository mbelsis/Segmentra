"""The Kubernetes lab: a real kind cluster, sample pods, and a Segmentra policy applied as a NetworkPolicy.

Segmentra talks to the cluster's API server, so nothing here needs SSH or a host firewall. The network
plugin (CNI) enforces what Segmentra applies. Needs `kind`; kubectl runs inside the cluster's own node.
Your current kubectl context is never changed.
"""
import concurrent.futures
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse

from .common import (
    ROOT, Api, Checks, LabError, connect_to_network, default_api_url, docker, ensure_approved_version, ensure_tag,
    find_api_containers, find_policy_set, find_tag, is_local, load_state, login, remove_policy_set, require_docker, save_state, say,
    versions_of, wait_for,
)

STATE_FILE = ROOT / ".demo-lab-k8s.json"
CLUSTER = "segmentra-lab"
CONTROL_PLANE = f"{CLUSTER}-control-plane"
NODES = [CONTROL_PLANE, f"{CLUSTER}-worker", f"{CLUSTER}-worker2"]
KIND_NETWORK = "kind"
RECORD_NAME = "demo-lab-k8s"
TAG_NAME = "demo-lab-k8s"
POLICY_NAME = "Kubernetes lab policy"
NETWORK_POLICY = "lab-shop-policy"
CNI_CHOICES = ["kindnet", "calico"]
CALICO_VERSION = "v3.30.3"
IMAGE = "busybox:1.36"

PROTECTED = "lab-shop"  # gets the policy
CONTROL = "lab-open"  # same pod, no policy: shows that the probes work and what the policy changes
CLIENTS_NS = "lab-clients"
NAMESPACES = [PROTECTED, CONTROL, CLIENTS_NS]
SERVICES = {"api": 8080, "metrics": 9100}
# pod: which worker it runs on. The clients sit on both, so traffic crosses nodes as well.
CLIENTS = {"frontend": 2, "monitoring": 1, "intruder": 2}
# The sample policy in one table: which client may use which service in the protected namespace.
ALLOWED = {("frontend", "api"), ("monitoring", "metrics")}


def require_kind():
    if not shutil.which("kind"):
        raise LabError("The Kubernetes lab needs kind, which was not found. See https://kind.sigs.k8s.io/docs/user/quick-start/#installation")


def kind(*args, timeout=600):
    done = subprocess.run(["kind", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if done.returncode != 0:
        raise LabError(f"kind {args[0]} failed: {done.stderr.decode('utf-8', 'replace').strip()}")
    return done.stdout.decode("utf-8", "replace")


def cluster_exists():
    return CLUSTER in kind("get", "clusters").split()


def kubectl(*args, check=True, timeout=120, stdin=None):
    """kubectl inside the control-plane node, so the computer running this needs none and no context changes."""
    command = ["docker", "exec", "-i", CONTROL_PLANE, "kubectl", *args]
    try:
        done = subprocess.run(command, input=(stdin or "").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        if check:
            raise LabError(f"kubectl {args[0]} timed out")
        return subprocess.CompletedProcess(command, 124, "", "timed out")
    stdout, stderr = done.stdout.decode("utf-8", "replace").strip(), done.stderr.decode("utf-8", "replace").strip()
    if check and done.returncode != 0:
        raise LabError(f"kubectl {' '.join(args[:3])} failed: {stderr or stdout}")
    return subprocess.CompletedProcess(command, done.returncode, stdout, stderr)


# --- Cluster and pods ------------------------------------------------------------------------------

def create_cluster(cni):
    networking = "networking:\n  disableDefaultCNI: true\n  podSubnet: 192.168.0.0/16\n" if cni == "calico" else ""
    config = (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n" + networking
        + "nodes:\n  - role: control-plane\n  - role: worker\n  - role: worker\n"
    )
    with tempfile.TemporaryDirectory() as folder:
        config_file = os.path.join(folder, "kind.yaml")
        with open(config_file, "w", encoding="utf-8") as output:
            output.write(config)
        # Its own kubeconfig file: otherwise kind would add this cluster to yours and switch your current context.
        kind("create", "cluster", "--name", CLUSTER, "--config", config_file, "--kubeconfig", os.path.join(folder, "kubeconfig"), "--wait", "0s")
    if cni == "calico":
        say(f"Installing Calico {CALICO_VERSION}")
        kubectl("apply", "-f", f"https://raw.githubusercontent.com/projectcalico/calico/{CALICO_VERSION}/manifests/calico.yaml", timeout=300)
    say("Waiting for the nodes")
    kubectl("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=420s", timeout=450)


def server_pod(namespace):
    script = "; ".join(f"mkdir -p /srv/{name} && echo {name} > /srv/{name}/index.html && httpd -p {port} -h /srv/{name}" for name, port in SERVICES.items()) + "; exec sleep 2147483647"
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "orders", "namespace": namespace, "labels": {"app": "orders"}},
        "spec": {"nodeName": f"{CLUSTER}-worker", "containers": [{"name": "orders", "image": IMAGE, "command": ["sh", "-c", script]}]},
    }


def client_pod(name):
    node = f"{CLUSTER}-worker" if CLIENTS[name] == 1 else f"{CLUSTER}-worker2"
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": CLIENTS_NS, "labels": {"app": name}},
        "spec": {"nodeName": node, "containers": [{"name": name, "image": IMAGE, "command": ["sleep", "2147483647"]}]},
    }


def deploy_pods():
    documents = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": n}} for n in NAMESPACES]
    documents += [server_pod(PROTECTED), server_pod(CONTROL)] + [client_pod(n) for n in CLIENTS]
    kubectl("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": documents}))
    for namespace in NAMESPACES:
        kubectl("wait", "--for=condition=Ready", "pod", "--all", "-n", namespace, "--timeout=300s", timeout=330)


def pod_ip(namespace, name):
    return kubectl("get", "pod", name, "-n", namespace, "-o", "jsonpath={.status.podIP}").stdout


# --- Segmentra -------------------------------------------------------------------------------------

def find_record(api, name=RECORD_NAME):
    for cluster in api.get("/k8s/clusters").get("clusters", []):
        if cluster["name"] == name:
            return cluster
    return None


def ensure_record(api, state):
    """Inside Docker the API reaches the cluster by its container name; outside, through the published port."""
    args = ["get", "kubeconfig", "--name", CLUSTER] + (["--internal"] if state["mode"] == "connected" else [])
    kubeconfig = kind(*args)
    body = {"name": RECORD_NAME, "description": "Sample cluster from scripts/demo-lab.py", "authType": "kubeconfig", "credentials": kubeconfig, "cni": state["cni"], "defaultNamespace": PROTECTED}
    existing = find_record(api)
    if existing:
        api.request("PUT", f"/k8s/clusters/{existing['id']}", body)
        return existing["id"]
    return api.post("/k8s/clusters", {**body, "apiServerUrl": "https://placeholder.invalid:6443"})["cluster"]["id"]


def ensure_workload(api, cluster_id, tag_id):
    """The frontend pod, registered and mapped to the tag: a rule naming the tag becomes a label selector."""
    workloads = api.get(f"/k8s/clusters/{cluster_id}/workloads").get("workloads", [])
    workload = next((w for w in workloads if w["name"] == "frontend" and w["namespace"] == CLIENTS_NS), None)
    if not workload:
        workload = api.post(f"/k8s/clusters/{cluster_id}/workloads", {"namespace": CLIENTS_NS, "kind": "Pod", "name": "frontend", "labels": {"app": "frontend"}})["workload"]
    if TAG_NAME not in (workload.get("tag_names") or []):
        api.post(f"/k8s/workloads/{workload['id']}/map-tag", {"tagId": tag_id})
    return workload["id"]


def sample_rules(tag_id, monitoring_ip):
    def rule(order, port, source_type, source, comment):
        return {
            "orderIndex": order, "direction": "IN", "action": "ALLOW", "protocol": "tcp", "ports": str(port), "sourceType": source_type,
            "sourceValue": source, "logMode": "NONE", "comment": comment, "usePolicyInterfaceScope": True,
        }

    return [
        rule(10, SERVICES["api"], "TAG", tag_id, "frontend-by-label"),
        rule(20, SERVICES["metrics"], "CIDR", f"{monitoring_ip}/32", "monitoring-by-ip"),
    ]


def ensure_version(api, state, tag_id, monitoring_ip):
    """A pod's address can change, for example after Docker restarts. A rule with the old one would match nothing."""
    policy = find_policy_set(api, POLICY_NAME)
    if policy and state.get("monitoring_ip") != monitoring_ip:
        for version in versions_of(api, policy["id"]):
            if version["status"] in ("APPROVED", "DEPLOYED"):
                api.post(f"/policy-versions/{version['id']}/archive")
    state["monitoring_ip"] = monitoring_ip
    save_state(STATE_FILE, state)
    return ensure_approved_version(
        api, POLICY_NAME, "Sample NetworkPolicy from scripts/demo-lab.py", {}, lambda: sample_rules(tag_id, monitoring_ip),
        scope={"scopeType": "TAG", "scopeTagId": tag_id},
    )


def generate(api, cluster_id, version_id, name=NETWORK_POLICY, namespace=PROTECTED):
    return api.post(f"/k8s/clusters/{cluster_id}/deploy-policy", {"policyVersionId": version_id, "namespace": namespace, "policyName": name})


def generate_and_apply(api, cluster_id, version_id):
    record = generate(api, cluster_id, version_id)["networkPolicy"]
    api.post(f"/k8s/clusters/{cluster_id}/network-policies/{record['id']}/apply")
    return record["id"]


def current_version(api):
    policy = find_policy_set(api, POLICY_NAME)
    usable = [v for v in versions_of(api, policy["id"]) if v["status"] in ("APPROVED", "DEPLOYED")] if policy else []
    return usable[0]["id"] if usable else None


# --- Traffic ---------------------------------------------------------------------------------------

def attempt(client, target_ip, service):
    """A real HTTP request from inside the client pod. True when the right service answered."""
    done = kubectl(
        "exec", client, "-n", CLIENTS_NS, "--", "wget", "-q", "-T", "2", "-O", "-", f"http://{target_ip}:{SERVICES[service]}/",
        check=False, timeout=20,
    )
    return done.returncode == 0 and service in done.stdout


def probe_all():
    targets = {PROTECTED: pod_ip(PROTECTED, "orders"), CONTROL: pod_ip(CONTROL, "orders")}
    flows = [(namespace, service, client) for namespace in (PROTECTED, CONTROL) for service in SERVICES for client in CLIENTS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = pool.map(lambda f: attempt(f[2], targets[f[0]], f[1]), flows)
        return dict(zip(flows, results))


def should_work(namespace, service, client):
    return namespace == CONTROL or (client, service) in ALLOWED


def differences_from_policy(results=None):
    results = probe_all() if results is None else results
    return [f"{c}>{n}:{s}" for (n, s, c), reached in results.items() if reached != should_work(n, s, c)]


def run_traffic(enforced=True):
    """Prints a table. Returns the number of results that differ from the policy."""
    results = probe_all()
    differences = 0
    say(f"  {'namespace':<12}{'service':<10}" + "".join(f"{client:<14}" for client in CLIENTS))
    for namespace in (PROTECTED, CONTROL):
        for service in SERVICES:
            cells = []
            for client in CLIENTS:
                reached = results[(namespace, service, client)]
                cell = "ok" if reached else "blocked"
                if enforced and reached != should_work(namespace, service, client):
                    differences += 1
                    cell += " (!)"
                cells.append(f"{cell:<14}")
            say(f"  {namespace:<12}{service:<10}" + "".join(cells))
    return differences


def require_state():
    state = load_state(STATE_FILE)
    if not state:
        raise LabError("The Kubernetes lab is not set up here. Run: python3 scripts/demo-lab.py up --lab k8s")
    return state


# --- Commands --------------------------------------------------------------------------------------

def cmd_up(args):
    require_docker()
    require_kind()
    if not is_local(args.api_url):
        raise LabError("The Kubernetes lab needs Segmentra on this machine, because it has to reach the cluster.")
    api = Api(args.api_url)
    say(f"Logging in to Segmentra at {args.api_url}")
    login(api, args)

    state = load_state(STATE_FILE)
    if not state and cluster_exists():
        raise LabError(f"A kind cluster called {CLUSTER} already exists and was not created by this script. Remove it first: kind delete cluster --name {CLUSTER}")
    if state and args.cni and args.cni != state["cni"]:
        raise LabError(f"The lab already uses {state['cni']}. Run `down --lab k8s` first to change the network plugin.")
    state = state or {"cni": args.cni or CNI_CHOICES[0]}
    # The Ansible runner plays no part here: Segmentra itself talks to the API server.
    port = urllib.parse.urlparse(args.api_url).port or 80
    api_containers = [n for n in find_api_containers(port) if "ansible-runner" not in n]
    state["mode"] = "connected" if api_containers else "published"
    state["api_containers"] = api_containers
    state["api_url"] = args.api_url
    save_state(STATE_FILE, state)
    existing = find_record(api)
    if existing and existing.get("description") != "Sample cluster from scripts/demo-lab.py":
        raise LabError(f"Segmentra already has a Kubernetes cluster called {RECORD_NAME} that is not part of the lab. It was left alone; rename it first.")

    if not cluster_exists():
        say(f"Creating a kind cluster with 3 nodes and {state['cni']} (the first time downloads about 1 GB and takes a few minutes)")
        create_cluster(state["cni"])
    else:
        for node in NODES:
            docker("start", node)
        kubectl("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=300s", timeout=330)
    say("Starting the sample pods")
    deploy_pods()
    if api_containers:
        say(f"Connecting {', '.join(api_containers)} to the cluster's network")
        connect_to_network(api_containers, KIND_NETWORK)

    say("Registering the cluster in Segmentra")
    tag_id = ensure_tag(api, TAG_NAME)
    cluster_id = ensure_record(api, state)
    connection = api.post(f"/k8s/clusters/{cluster_id}/test-connection")
    say(f"  Connected to Kubernetes {connection.get('serverVersion')}")
    ensure_workload(api, cluster_id, tag_id)

    already_applied = kubectl("get", "networkpolicy", NETWORK_POLICY, "-n", PROTECTED, check=False).returncode == 0
    say("\nBefore applying: the policy from an earlier run is active" if already_applied else "\nBefore the policy: every pod reaches every pod")
    run_traffic(enforced=False)

    say(f"\nCreating and approving '{POLICY_NAME}', then applying it as a NetworkPolicy")
    version_id = ensure_version(api, state, tag_id, pod_ip(CLIENTS_NS, "monitoring"))
    generate_and_apply(api, cluster_id, version_id)

    # The network plugin programs a new policy a moment after the API server accepts it.
    wait_for(lambda: not differences_from_policy(), 30)
    say("\nAfter the policy")
    differences = run_traffic()
    if differences:
        raise LabError(f"{differences} results differ from the policy, marked (!).")

    say("\nReady. Every result matches the policy.")
    say(f"  {PROTECTED}: frontend reaches api (by label), monitoring reaches metrics (by IP), intruder reaches nothing")
    say(f"  {CONTROL} has no policy, so everything still reaches it")
    say("\nTry this in Segmentra:")
    say("  Kubernetes: the cluster, its workload and the applied NetworkPolicy")
    say("\n  python3 scripts/demo-lab.py traffic --lab k8s   send the traffic again")
    say("  python3 scripts/demo-lab.py check --lab k8s     test Segmentra's Kubernetes features against this lab")
    say("  python3 scripts/demo-lab.py down --lab k8s      remove the lab")


def cmd_traffic(args):
    require_docker()
    require_state()
    if docker("exec", CONTROL_PLANE, "true", check=False).returncode != 0:
        raise LabError("The cluster is not running. Run: python3 scripts/demo-lab.py up --lab k8s")
    differences = 0
    for round_number in range(args.repeat):
        if round_number:
            time.sleep(args.interval)
        if args.repeat > 1:
            say(f"Round {round_number + 1} of {args.repeat}")
        differences = run_traffic()
    if differences:
        say(f"\n{differences} results differ from the policy, marked (!).")
        return 1
    say("\nEvery result matches the policy.")
    return 0


def cmd_status(args):
    require_docker()
    state = load_state(STATE_FILE)
    say(f"Set up from this folder: {'yes' if state else 'no'}")
    if state:
        say(f"Cluster: {CLUSTER}, network plugin {state['cni']}")
    for name in NODES:
        running = docker("inspect", "--format", "{{.State.Status}}", name, check=False)
        say(f"  {name}: {running.stdout if running.returncode == 0 else 'not created'}")
    if state and docker("exec", CONTROL_PLANE, "true", check=False).returncode == 0:
        say("\n" + kubectl("get", "pods", "-A", "-l", "app", "-o", "wide", check=False).stdout)
        say("\n" + kubectl("get", "networkpolicy", "-A", check=False).stdout)
    return 0


def cmd_check(args):
    """Segmentra's Kubernetes features against the real cluster. Changes the lab for a while, then restores it."""
    require_docker()
    state = require_state()
    api = Api(args.api_url or state.get("api_url") or default_api_url())
    login(api, args)
    record = find_record(api)
    version_id = current_version(api)
    tag = find_tag(api, TAG_NAME)
    if not record or not version_id or not tag:
        raise LabError("The Kubernetes lab is not in this Segmentra. Run: python3 scripts/demo-lab.py up --lab k8s")
    cluster_id = record["id"]
    base = f"/k8s/clusters/{cluster_id}"
    checks = Checks()
    check = checks.check

    def records():
        return api.get(f"{base}/network-policies").get("networkPolicies", [])

    def applied_id():
        return next(r["id"] for r in records() if r["policy_name"] == NETWORK_POLICY and r["status"] == "APPLIED")

    def sync_state(record_id):
        return api.post(f"{base}/network-policies/{record_id}/check").get("state")

    def settled():
        return wait_for(lambda: not differences_from_policy(), 30)

    say("Traffic and the connection")
    wrong = differences_from_policy()
    check("every client reaches only what the policy allows", not wrong, str(wrong) if wrong else "")
    connection = api.post(f"{base}/test-connection")
    check("Segmentra can reach the API server", connection.get("ok") is True, str(connection.get("serverVersion")))
    answers = json.dumps(api.get("/k8s/clusters")) + json.dumps(api.get(base))
    check("the API never returns the stored credentials", "client-key-data" not in answers and "BEGIN CERTIFICATE" not in answers and record.get("has_credentials") is True)

    say("\nThe generated NetworkPolicy")
    live = json.loads(kubectl("get", "networkpolicy", NETWORK_POLICY, "-n", PROTECTED, "-o", "json").stdout)
    peers = [peer for rule in live["spec"].get("ingress", []) for peer in rule.get("from", [])]
    check("the rule naming a tag became a label selector", any(p.get("podSelector", {}).get("matchLabels", {}).get("app") == "frontend" for p in peers))
    check("the rule naming an address became an ipBlock", any(p.get("ipBlock", {}).get("cidr") == f"{state['monitoring_ip']}/32" for p in peers))
    check("it covers the whole namespace", live["spec"].get("podSelector") in ({}, None))
    check("it is labelled as managed by Segmentra", live["metadata"]["labels"].get("app.kubernetes.io/managed-by") == "segmentra")
    current = applied_id()
    check("Segmentra reports it as in sync", sync_state(current) == "IN_SYNC")

    say("\nDrift")
    patch = json.dumps([{"op": "add", "path": "/spec/ingress/-", "value": {"ports": [{"port": 8080, "protocol": "TCP"}]}}])
    kubectl("patch", "networkpolicy", NETWORK_POLICY, "-n", PROTECTED, "--type=json", "-p", patch)
    check("a policy edited by hand is reported as drifted", sync_state(current) == "DRIFTED")
    opened = wait_for(lambda: attempt("intruder", pod_ip(PROTECTED, "orders"), "api"), 20)
    check("and the edit really opened the service to the intruder", opened)
    api.post(f"{base}/network-policies/{current}/apply")
    check("applying again repairs it", sync_state(current) == "IN_SYNC" and settled())
    kubectl("delete", "networkpolicy", NETWORK_POLICY, "-n", PROTECTED)
    check("a policy deleted by hand is reported as missing", sync_state(current) == "MISSING")
    api.post(f"{base}/network-policies/{current}/apply")
    check("applying again restores it", sync_state(current) == "IN_SYNC" and settled())

    say("\nSafety")
    dry_before = kubectl("get", "networkpolicy", NETWORK_POLICY, "-n", PROTECTED, "-o", "jsonpath={.metadata.resourceVersion}").stdout
    dry = api.post(f"{base}/network-policies/{current}/apply", {"dryRun": True})
    dry_after = kubectl("get", "networkpolicy", NETWORK_POLICY, "-n", PROTECTED, "-o", "jsonpath={.metadata.resourceVersion}").stdout
    check("a dry run validates without changing anything", dry.get("dryRun") is True and dry_before == dry_after)
    current = generate_and_apply(api, cluster_id, version_id)
    older = next(r for r in records() if r["policy_name"] == NETWORK_POLICY and r["status"] == "SUPERSEDED")
    status, _ = api.request("POST", f"{base}/network-policies/{older['id']}/apply", {}, ok=(200, 409))
    check("an older manifest cannot be applied over a newer one", status == 409)
    handmade = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "handmade", "namespace": PROTECTED},
        "spec": {"podSelector": {"matchLabels": {"app": "nothing"}}, "policyTypes": ["Ingress"]},
    }
    kubectl("apply", "-f", "-", stdin=json.dumps(handmade))
    attempted = generate(api, cluster_id, version_id, name="handmade")["networkPolicy"]["id"]
    applied, _ = api.request("POST", f"{base}/network-policies/{attempted}/apply", {}, ok=(200, 409))
    removed, _ = api.request("POST", f"{base}/network-policies/{attempted}/remove", {}, ok=(200, 409))
    untouched = kubectl("get", "networkpolicy", "handmade", "-n", PROTECTED, "-o", "jsonpath={.spec.podSelector.matchLabels.app}", check=False).stdout
    check("a policy Segmentra did not create is not overwritten or deleted", applied == 409 and removed == 409 and untouched == "nothing")
    kubectl("delete", "networkpolicy", "handmade", "-n", PROTECTED)

    say("\nA service account that may only read")
    read_only = [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "lab-reader", "namespace": "kube-system"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "lab-reader"}, "rules": [{"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["get", "list"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "lab-reader"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "lab-reader"}, "subjects": [{"kind": "ServiceAccount", "name": "lab-reader", "namespace": "kube-system"}]},
    ]
    kubectl("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": read_only}))
    token = kubectl("create", "token", "lab-reader", "-n", "kube-system", "--duration=1h").stdout
    reader = api.post("/k8s/clusters", {
        "name": f"{RECORD_NAME}-reader", "description": "Sample cluster from scripts/demo-lab.py", "apiServerUrl": api.get(base)["cluster"]["api_server_url"],
        "authType": "token", "credentials": token, "tlsSkipVerify": True, "cni": state["cni"], "defaultNamespace": PROTECTED,
    }, ok=(200, 201))["cluster"]
    try:
        row = api.post(f"/k8s/clusters/{reader['id']}/deploy-policy", {"policyVersionId": version_id, "namespace": PROTECTED, "policyName": "lab-reader-test"})["networkPolicy"]
        status, body = api.request("POST", f"/k8s/clusters/{reader['id']}/network-policies/{row['id']}/apply", {}, ok=(200, 400, 403, 409, 502))
        check("applying with it is refused, and the reason is reported", status != 200 and "forbidden" in str(body).lower(), f"{status}")
        rows = api.get(f"/k8s/clusters/{reader['id']}/network-policies").get("networkPolicies", [])
        check("the failure is recorded on the policy", rows and rows[0].get("status") == "FAILED" and rows[0].get("last_error"))
    finally:
        api.request("DELETE", f"/k8s/clusters/{reader['id']}", ok=(200, 204, 404))
    kubectl("delete", "clusterrolebinding,clusterrole", "lab-reader", check=False)
    kubectl("delete", "serviceaccount", "lab-reader", "-n", "kube-system", check=False)

    say("\nWarning for a network plugin that ignores address rules")
    cilium = api.post("/k8s/clusters", {
        "name": f"{RECORD_NAME}-cilium", "description": "Sample cluster from scripts/demo-lab.py", "apiServerUrl": api.get(base)["cluster"]["api_server_url"], "cni": "cilium", "defaultNamespace": PROTECTED,
    }, ok=(200, 201))["cluster"]
    try:
        warnings = api.post(f"/k8s/clusters/{cilium['id']}/deploy-policy", {"policyVersionId": version_id, "namespace": PROTECTED, "policyName": "lab-cilium-test"}).get("warnings", [])
        check("generating for Cilium warns about ipBlock", any("ipBlock" in w for w in warnings))
    finally:
        api.request("DELETE", f"/k8s/clusters/{cilium['id']}", ok=(200, 204, 404))
    warnings = generate(api, cluster_id, version_id)
    check(f"generating for {state['cni']} does not", not any("ipBlock" in w for w in warnings.get("warnings", [])))
    current = generate_and_apply(api, cluster_id, version_id)

    say("\nLabels or addresses when a pod restarts")
    frontend_before = pod_ip(CLIENTS_NS, "frontend")
    kubectl("delete", "pod", "frontend", "-n", CLIENTS_NS, "--wait=true", timeout=120)
    kubectl("apply", "-f", "-", stdin=json.dumps(client_pod("frontend")))
    kubectl("wait", "--for=condition=Ready", "pod", "frontend", "-n", CLIENTS_NS, "--timeout=120s", timeout=150)
    frontend_after = pod_ip(CLIENTS_NS, "frontend")
    check("a restarted pod comes back with a new address", frontend_before != frontend_after, f"{frontend_before} to {frontend_after}")
    check("the rule by label still lets it in, with no new policy", wait_for(lambda: attempt("frontend", pod_ip(PROTECTED, "orders"), "api"), 20))

    say("\nTaking the tag off the workload")
    workload = next(w for w in api.get(f"{base}/workloads")["workloads"] if w["name"] == "frontend")
    api.request("DELETE", f"/k8s/workloads/{workload['id']}/tags/{tag['id']}")
    current = generate_and_apply(api, cluster_id, version_id)
    check("after generating and applying again, the frontend is blocked", wait_for(lambda: not attempt("frontend", pod_ip(PROTECTED, "orders"), "api"), 20))
    api.post(f"/k8s/workloads/{workload['id']}/map-tag", {"tagId": tag["id"]})
    current = generate_and_apply(api, cluster_id, version_id)
    check("with the tag back, every flow matches the policy again", settled())

    say("\nRemoving the policy through Segmentra")
    removed = api.post(f"{base}/network-policies/{current}/remove")
    gone = kubectl("get", "networkpolicy", NETWORK_POLICY, "-n", PROTECTED, check=False).returncode != 0
    check("it is gone from the cluster", removed.get("ok") is True and gone)
    check("Segmentra reports it as missing", sync_state(current) == "MISSING")
    check("and the namespace is open again", wait_for(lambda: attempt("intruder", pod_ip(PROTECTED, "orders"), "api"), 20))
    generate_and_apply(api, cluster_id, version_id)
    check("applying it again blocks the intruder and every flow matches", settled())

    say(f"\n{checks.count - len(checks.failed)} of {checks.count} checks passed")
    if checks.failed:
        raise LabError("Failed: " + "; ".join(checks.failed))
    return 0


def clean_up_inventory(api):
    kept = []
    for name in (RECORD_NAME, f"{RECORD_NAME}-reader", f"{RECORD_NAME}-cilium"):
        record = find_record(api, name)
        if record and record.get("description") == "Sample cluster from scripts/demo-lab.py":
            api.request("DELETE", f"/k8s/clusters/{record['id']}", ok=(200, 204, 400, 404, 409))
    if not remove_policy_set(api, POLICY_NAME):
        kept.append(f"policy '{POLICY_NAME}' (archived)")
    tag = find_tag(api, TAG_NAME)
    if tag:
        status, _ = api.request("DELETE", f"/tags/{tag['id']}", ok=(200, 204, 400, 404, 409))
        if status not in (200, 204):
            kept.append(f"tag {TAG_NAME}")
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
        say(f"  Warning: Segmentra was not cleaned up ({error}). Remove the cluster {RECORD_NAME} and '{POLICY_NAME}' by hand if they remain.")

    for name in state.get("api_containers") or []:
        docker("network", "disconnect", KIND_NETWORK, name, check=False)
    # Only with the lab's state: a cluster of this name without it was not created here.
    if state and shutil.which("kind") and cluster_exists():
        say(f"Removing the kind cluster {CLUSTER}")
        kind("delete", "cluster", "--name", CLUSTER)
    if STATE_FILE.exists():
        STATE_FILE.unlink()

    say("Done.")
    if kept:
        say(f"Segmentra keeps history, so these remain: {', '.join(kept)}. Running `up` again reuses them.")
    if args.remove_images:
        say("The kind node image stays, because other kind clusters may use it. Remove it with: docker rmi kindest/node:<version>")
    return 0
