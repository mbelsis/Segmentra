#!/usr/bin/env python3
"""Build a small test environment for Segmentra with one command.

  python3 scripts/demo-lab.py up        three Docker machines, inventory, a sample policy, deployed
  python3 scripts/demo-lab.py traffic   ping, ssh, telnet and curl between the machines
  python3 scripts/demo-lab.py siem      what the sample SIEM received from Segmentra
  python3 scripts/demo-lab.py status    what exists right now
  python3 scripts/demo-lab.py down      remove it again

Needs Python 3.8+, Docker and a running Segmentra (./install.sh --production or ./start.sh dev).
Uses only the Python standard library. Run with --help on a command for its options.

Everything is created through Segmentra's normal API, and nothing global is changed unless you pass
--set-executor-ssh. FOR TESTING ONLY: the machines are privileged containers with a known user password.
"""
import argparse
import collections
import getpass
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / ".demo-lab.json"
BUILD_DIR = ROOT / "infra" / "demo-lab"
LABEL = "segmentra.demo-lab"
NETWORK = "segmentra-demo-lab"
TAG_NAME = "demo-lab"
CREDENTIAL_NAME = "demo-lab-credential"
POLICY_NAME = "Demo lab policy"
APPROVER_NAME = "demo-lab-approver"
# Containers have no boot to survive, so the readiness note about rules being lost on reboot does not matter here.
START_BODY = {"acceptReadinessNotes": True}
MACHINES = ["test-a", "test-b", "test-c"]
FIRST_SSH_PORT = 22201  # host ports, only when the API runs outside Docker
NF_LOG_SYSCTL = "/proc/sys/net/netfilter/nf_log_all_netns"
SYSCTL_IMAGE = "alpine:3.20"

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


class LabError(Exception):
    pass


def say(text=""):
    print(text, flush=True)


# --- Docker ----------------------------------------------------------------------------------------

def docker(*args, check=True, timeout=None, stream=False):
    command = ["docker", *args]
    try:
        if stream:
            done = subprocess.run(command, timeout=timeout)
            stdout, stderr = "", ""
        else:
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            stdout = done.stdout.decode("utf-8", "replace").strip()
            stderr = done.stderr.decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        if check:
            raise LabError(f"docker {args[0]} timed out")
        return subprocess.CompletedProcess(command, 124, "", "timed out")
    if check and done.returncode != 0:
        raise LabError(f"docker {' '.join(args[:3])} failed: {stderr or stdout}")
    return subprocess.CompletedProcess(command, done.returncode, stdout, stderr)


def require_docker():
    if not shutil.which("docker"):
        raise LabError("Docker was not found. Install Docker and try again.")
    if docker("version", "--format", "{{.Server.Version}}", check=False, timeout=30).returncode != 0:
        raise LabError("Docker is installed but not running. Start it and try again.")


def labelled(kind, name):
    """None when it does not exist, otherwise whether this script created it."""
    done = docker(kind, "inspect", "--format", '{{index .Config.Labels "%s"}}' % LABEL, name, check=False)
    return None if done.returncode != 0 else done.stdout == "1"


def lab_ips(subnet):
    prefix = subnet.rsplit(".", 1)[0]
    return {name: f"{prefix}.{11 + i}" for i, name in enumerate(MACHINES)}


def syslog_ip(subnet):
    return subnet.rsplit(".", 1)[0] + ".20"


def build_images():
    say("Building the images test-a, test-b and test-c (the first time takes a minute or two)")
    names = [*MACHINES, SYSLOG_NAME]
    for name in names:
        if labelled("image", name) is False:
            raise LabError(f"An image called {name} already exists and was not created by this script. Remove or rename it first.")
    docker("build", "--quiet", "-t", names[0], str(BUILD_DIR))
    for name in names[1:]:
        docker("tag", names[0], name)


def create_network(subnet):
    if docker("network", "inspect", NETWORK, check=False).returncode == 0:
        return
    done = docker("network", "create", "--subnet", subnet, "--label", f"{LABEL}=1", NETWORK, check=False)
    if done.returncode != 0:
        raise LabError(f"Could not create the network on {subnet}: {done.stderr}\nPick a free range with --subnet.")


def generate_ssh_key():
    """Made inside the lab's own image, so the computer running this script needs no ssh tools."""
    script = "ssh-keygen -q -t ed25519 -N '' -C demo-lab -f /tmp/k && cat /tmp/k.pub && cat /tmp/k"
    done = docker("run", "--rm", "--entrypoint", "sh", MACHINES[0], "-c", script)
    public, _, private = done.stdout.partition("\n")
    return public.strip(), private.strip() + "\n"


def start_machines(state):
    ips = lab_ips(state["subnet"])
    for i, name in enumerate(MACHINES):
        existing = labelled("container", name)
        if existing is False:
            raise LabError(f"A container called {name} already exists and was not created by this script. Remove or rename it first.")
        if existing:
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
    existing = labelled("container", SYSLOG_NAME)
    if existing is False:
        raise LabError(f"A container called {SYSLOG_NAME} already exists and was not created by this script. Remove or rename it first.")
    if existing:
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


def find_api_containers(port):
    """The API container (published on the API port) and its Ansible runner, when it runs in Docker."""
    found = docker("ps", "--filter", f"publish={port}", "--format", '{{.Names}}\t{{.Label "com.docker.compose.project"}}').stdout
    if not found:
        return []
    name, _, project = found.splitlines()[0].partition("\t")
    names = [name]
    if project:
        others = docker("ps", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.Names}}").stdout
        names += [n for n in others.splitlines() if "ansible-runner" in n]
    return names


def connect_to_network(names):
    for name in names:
        done = docker("network", "connect", NETWORK, name, check=False)
        if done.returncode != 0 and "already exists" not in done.stderr:
            raise LabError(f"Could not connect {name} to the lab network: {done.stderr}")


def enable_container_firewall_logs(state):
    """Kernels only log firewall lines from containers with this setting. The old value is put back by `down`."""
    script = f"cat {NF_LOG_SYSCTL} 2>/dev/null; echo 1 > {NF_LOG_SYSCTL}"
    done = docker("run", "--rm", "--privileged", "--network", "host", SYSCTL_IMAGE, "sh", "-c", script, check=False)
    if done.returncode != 0:
        say("  Warning: could not turn on container firewall logging, so Peek at Logs may stay empty.")
    elif "nf_log_previous" not in state:
        state["nf_log_previous"] = done.stdout.strip() or None
        save_state(state)


def restore_container_firewall_logs(state):
    previous = state.get("nf_log_previous")
    if previous in ("0", "1"):
        docker("run", "--rm", "--privileged", "--network", "host", SYSCTL_IMAGE, "sh", "-c", f"echo {previous} > {NF_LOG_SYSCTL}", check=False)


# --- Segmentra API ---------------------------------------------------------------------------------

class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.token = None

    def request(self, method, path, body=None, ok=(200, 201, 202), token=None):
        """Returns (status, json). Raises LabError for statuses not in `ok`."""
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("content-type", "application/json")
        bearer = token or self.token
        if bearer:
            request.add_header("authorization", f"Bearer {bearer}")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                status, text = response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            status, text = error.code, error.read().decode("utf-8", "replace")
        except OSError as error:
            raise LabError(f"Cannot reach Segmentra at {self.base}: {error}\nIs it running? Use --api-url if it is on another port.")
        if status not in ok:
            raise LabError(f"{method} {path} returned {status}: {text[:400]}")
        try:
            return status, json.loads(text) if text else {}
        except ValueError:
            raise LabError(f"{method} {path} did not return JSON. Is {self.base} really the Segmentra API?")

    def get(self, path):
        return self.request("GET", path)[1]

    def post(self, path, body=None, ok=(200, 201, 202)):
        return self.request("POST", path, body if body is not None else {}, ok=ok)[1]


def read_dotenv():
    values = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
            if match:
                values[match.group(1)] = match.group(2).strip().strip("\"'")
    return values


def login(api, args):
    """--password, then the environment, then .env, then the development default, then ask."""
    dotenv = read_dotenv()
    candidates = [args.password, os.environ.get("SEGMENTRA_ADMIN_PASSWORD"), dotenv.get("SEGMENTRA_ADMIN_PASSWORD"), "admin123"]
    for password in candidates:
        if password and try_login(api, args.username, password):
            return
    if sys.stdin.isatty():
        if try_login(api, args.username, getpass.getpass(f"Segmentra password for {args.username}: ")):
            return
    raise LabError(f"Could not log in to Segmentra as {args.username}. Use --username, and --password or SEGMENTRA_ADMIN_PASSWORD.")


def try_login(api, username, password):
    status, data = api.request("POST", "/auth/login", {"username": username, "password": password}, ok=(200, 400, 401, 403))
    if status == 200 and data.get("token"):
        api.token = data["token"]
        return True
    return False


def find_host(api, name):
    query = urllib.parse.urlencode({"hostname": name, "limit": 1000})
    for host in api.get(f"/hosts?{query}").get("hosts", []):
        if host["hostname"] == name:
            return host
    return None


def has_lab_tag(host):
    return any((t.get("name") if isinstance(t, dict) else t) == TAG_NAME for t in host.get("tags") or [])


def ensure_tag(api):
    for tag in api.get("/tags").get("tags", []):
        if tag["name"] == TAG_NAME:
            return tag["id"]
    return api.post("/tags", {"name": TAG_NAME, "description": "Created by scripts/demo-lab.py"})["tag"]["id"]


def ensure_credential(api, tag_id, private_key):
    """Scoped to the lab's tag, so it is never chosen for any other host."""
    body = {"name": CREDENTIAL_NAME, "username": "segmentra", "scopeType": "TAG", "scopeId": tag_id, "priority": 0, "sudoMode": "NOPASSWD"}
    existing = find_credential(api)
    if existing:
        # A stored key cannot be replaced through an update.
        api.request("DELETE", f"/ssh-credentials/{existing['id']}")
    api.post("/ssh-credentials", {**body, "authMethod": "KEY", "privateKeyPem": private_key})


def find_credential(api):
    for credential in api.get("/ssh-credentials").get("sshCredentials", []):
        if credential["name"] == CREDENTIAL_NAME:
            return credential
    return None


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
        if host and not has_lab_tag(host):
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


def find_policy_set(api):
    for policy in api.get("/policy-sets").get("policySets", []):
        if policy["name"] == POLICY_NAME:
            return policy
    return None


def versions_of(api, policy_set_id):
    return api.get(f"/policy-sets/{policy_set_id}/versions").get("versions", [])


def ensure_approved_version(api, state, host_ids):
    policy = find_policy_set(api)
    if policy:
        usable = [v for v in versions_of(api, policy["id"]) if v["status"] in ("APPROVED", "DEPLOYED")]
        if usable:
            return usable[0]["id"]
        policy_id = policy["id"]
    else:
        policy_id = api.post("/policy-sets", {
            "name": POLICY_NAME, "description": "Sample policy from scripts/demo-lab.py",
            "scopeType": "HOST_LIST", "hostIds": list(host_ids.values()),
        })["policySet"]["id"]
    version_id = api.post(f"/policy-sets/{policy_id}/versions", {"changeSummary": "Sample rules", "interfaceScopeType": "ALL_INTERFACES"})["version"]["id"]
    for rule in sample_rules(state):
        api.post(f"/policy-versions/{version_id}/rules", rule)
    api.post(f"/policy-versions/{version_id}/submit-approval")
    approve_as_second_person(api, f"/policy-versions/{version_id}/approve")
    return version_id


def approve_as_second_person(api, path):
    """Segmentra requires a second person to approve changes. This account is switched on only for the
    approval. It is never deleted: deleting a user erases the record of what that user approved."""
    password = secrets.token_urlsafe(24)
    users = api.get("/admin/users").get("users", [])
    user = next((u for u in users if u["username"] == APPROVER_NAME), None)
    if user:
        user_id = user["id"]
        api.request("PUT", f"/admin/users/{user_id}", {"isActive": True})
        api.post(f"/admin/users/{user_id}/reset-password", {"newPassword": password})
    else:
        created = api.post("/admin/users", {"username": APPROVER_NAME, "displayName": "Demo lab approver", "password": password, "roles": ["approver"], "isActive": True})
        user_id = created.get("user", created)["id"]
    try:
        token = api.request("POST", "/auth/login", {"username": APPROVER_NAME, "password": password})[1]["token"]
        api.request("POST", path, {}, token=token)
    finally:
        api.request("PUT", f"/admin/users/{user_id}", {"isActive": False})


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


def check_executor(api, state, args):
    """The default executor is Ansible, which needs a runner container that can reach the machines."""
    executor = api.get("/admin/executor-setting").get("executor", "ansible")
    if executor == "ssh" or state["mode"] == "connected" and state.get("runner"):
        return
    if not args.set_executor_ssh:
        raise LabError(
            f"Deployments currently use the {executor} executor, which cannot reach the demo machines from this setup.\n"
            "Switch it under Admin, or run this again with --set-executor-ssh. That setting applies to every deployment."
        )
    api.request("PUT", "/admin/executor-setting", {"executor": "ssh"})
    say("  Deployment executor set to SSH, as requested")


def deploy(api, version_id, host_ids):
    created = api.post("/deployments", {"policyVersionId": version_id, "mode": "FULL", "targetQuery": {"hosts": list(host_ids.values()), "tags": [], "vlans": []}})
    deployment_id = created["deployment"]["id"]
    status, started = api.request("POST", f"/deployments/{deployment_id}/start", START_BODY, ok=(200, 201, 202, 409))
    if status == 409:
        if started.get("error") != "deployment_requires_approval":
            raise LabError(f"The deployment could not start: {started}")
        approve_as_second_person(api, f"/deployments/{deployment_id}/approve")
        api.post(f"/deployments/{deployment_id}/start", START_BODY)
    deadline = time.time() + 300
    while time.time() < deadline:
        status = api.get(f"/deployments/{deployment_id}")["deployment"]["status"]
        if status == "SUCCEEDED":
            return
        if status in ("FAILED", "PARTIAL", "CANCELLED"):
            hosts = api.get(f"/deployments/{deployment_id}/hosts").get("hosts", [])
            details = "\n".join(f"  {h.get('hostname')}: {h.get('status')} {str(h.get('message') or '').strip()[:300]}" for h in hosts)
            hint = ""
            if "Host key verification failed" in details:
                hint = ("\nA machine has a new SSH host key (its image was rebuilt from scratch). Remove its old entry from the"
                        " known_hosts file of the user running the API, then run this again.")
            raise LabError(f"The deployment ended as {status}:\n{details}{hint}")
        time.sleep(2)
    raise LabError("The deployment did not finish within 5 minutes.")


# --- Sample traffic --------------------------------------------------------------------------------

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


# --- State -----------------------------------------------------------------------------------------

def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return None


def save_state(state):
    STATE_FILE.touch(mode=0o600)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def require_state():
    state = load_state()
    if not state:
        raise LabError("The demo lab is not set up here. Run: python3 scripts/demo-lab.py up")
    return state


def default_api_url():
    return f"http://127.0.0.1:{read_dotenv().get('API_PORT') or 8080}/api"


def is_local(url):
    return urllib.parse.urlparse(url).hostname in ("127.0.0.1", "localhost", "::1")


# --- Commands --------------------------------------------------------------------------------------

def cmd_up(args):
    require_docker()
    if not is_local(args.api_url):
        raise LabError("The demo lab needs Segmentra on this machine, because its Docker containers have to reach each other.")
    api = Api(args.api_url)
    say(f"Logging in to Segmentra at {args.api_url}")
    login(api, args)

    state = load_state() or {"subnet": args.subnet}
    port = urllib.parse.urlparse(args.api_url).port or 80
    api_containers = find_api_containers(port)
    state["mode"] = "connected" if api_containers else "published"
    state["api_containers"] = api_containers
    state["runner"] = any("ansible-runner" in n for n in api_containers)
    state["api_url"] = args.api_url
    save_state(state)
    # Checked before anything is created in the inventory, so a refusal leaves nothing behind.
    for name in MACHINES:
        host = find_host(api, name)
        if host and not has_lab_tag(host):
            raise LabError(f"Your inventory already has a host called {name} that is not part of the demo lab. It was left alone; rename it first.")
    check_executor(api, state, args)

    build_images()
    if "mgmt_private_key" not in state:
        state["mgmt_public_key"], state["mgmt_private_key"] = generate_ssh_key()
        save_state(state)
    create_network(state["subnet"])
    start_machines(state)
    if api_containers:
        say(f"Connecting {', '.join(api_containers)} to the lab network")
        connect_to_network(api_containers)
    enable_container_firewall_logs(state)

    say("Adding the machines to the inventory")
    tag_id = ensure_tag(api)
    ensure_credential(api, tag_id, state["mgmt_private_key"])
    host_ids = ensure_hosts(api, state, tag_id)

    say("Connecting the sample SIEM")
    start_syslog_receiver(state)
    siem_ids = ensure_siem(api, state)

    say("\nBefore the policy: everything is open")
    run_traffic(state, enforced=False)

    say(f"\nCreating, approving and deploying '{POLICY_NAME}'")
    version_id = ensure_approved_version(api, state, host_ids)
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
    state = load_state()
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


def stop_sessions(api, host):
    """A log-only session left running would keep trying to restore a machine that no longer exists."""
    for path, finish in (("/policy-test/sessions", "stop"), ("/troubleshoot/audit/sessions", "restore")):
        status, data = api.request("GET", f"{path}?hostId={host['id']}", ok=(200, 400, 404))
        if status != 200:
            continue
        for session in data.get("sessions", []):
            if session.get("host_id") == host["id"] and session.get("status") == "RUNNING":
                api.request("POST", f"{path}/{session['id']}/{finish}", {}, ok=(200, 400, 404, 409, 500))


def clean_up_inventory(api):
    kept = []
    hosts = [h for h in (find_host(api, name) for name in MACHINES) if h and has_lab_tag(h)]
    for host in hosts:
        stop_sessions(api, host)
    policy = find_policy_set(api)
    if policy:
        for version in versions_of(api, policy["id"]):
            if version["status"] in ("APPROVED", "DEPLOYED", "PENDING_APPROVAL"):
                api.request("POST", f"/policy-versions/{version['id']}/archive", {}, ok=(200, 201, 400, 404, 409))
            elif version["status"] in ("DRAFT", "REJECTED"):
                api.request("DELETE", f"/policy-versions/{version['id']}", ok=(200, 204, 400, 404, 409))
        api.request("DELETE", f"/policy-sets/{policy['id']}", ok=(200, 204, 400, 404, 409))
        if find_policy_set(api):
            kept.append(f"policy '{POLICY_NAME}' (archived)")
    for host in hosts:
        status, _ = api.request("DELETE", f"/hosts/{host['id']}", ok=(200, 204, 400, 404, 409))
        if status not in (200, 204):
            api.request("PUT", f"/hosts/{host['id']}", {"enabled": False})
            kept.append(f"host {host['hostname']} (disabled)")
    for integration in siem_integrations(api).values():
        api.request("DELETE", f"/integrations/{integration['id']}", ok=(200, 204, 400, 404, 409))
    credential = find_credential(api)
    if credential:
        api.request("DELETE", f"/ssh-credentials/{credential['id']}", ok=(200, 204, 400, 404, 409))
    for tag in api.get("/tags").get("tags", []):
        if tag["name"] == TAG_NAME and not any("host " in k for k in kept):
            api.request("DELETE", f"/tags/{tag['id']}", ok=(200, 204, 400, 404, 409))
    return kept


def cmd_down(args):
    require_docker()
    state = load_state() or {}
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
    restore_container_firewall_logs(state)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--api-url", help="Segmentra API (default: http://127.0.0.1:<API_PORT from .env, or 8080>/api)")
    common.add_argument("--username", default="admin", help="Segmentra admin user (default: admin)")
    common.add_argument("--password", help="its password (default: SEGMENTRA_ADMIN_PASSWORD, .env, the dev default, then it asks)")
    commands = parser.add_subparsers(dest="command", required=True)

    up = commands.add_parser("up", parents=[common], help="create everything and deploy the sample policy")
    up.add_argument("--subnet", default="172.28.77.0/24", help="network for the machines (a free /24, default: %(default)s)")
    up.add_argument("--set-executor-ssh", action="store_true", help="switch deployments to the SSH executor; a global setting, only needed when Ansible cannot reach the machines")
    up.set_defaults(run=cmd_up)

    traffic = commands.add_parser("traffic", help="run ping, ssh, telnet and curl between the machines")
    traffic.add_argument("--repeat", type=int, default=1, help="how many rounds (default: 1)")
    traffic.add_argument("--interval", type=int, default=10, help="seconds between rounds (default: 10)")
    traffic.set_defaults(run=cmd_traffic)

    siem = commands.add_parser("siem", help="show what the sample SIEM received")
    siem.add_argument("--last", type=int, default=15, help="how many of the newest messages to show (default: 15)")
    siem.add_argument("--by-action", action="store_true", help="also count the messages per action")
    siem.set_defaults(run=cmd_siem)

    commands.add_parser("status", help="show what exists").set_defaults(run=cmd_status)

    down = commands.add_parser("down", parents=[common], help="remove the lab")
    down.add_argument("--remove-images", action="store_true", help="also remove the lab's images")
    down.set_defaults(run=cmd_down)

    args = parser.parse_args()
    if args.command == "up" and not args.api_url:
        args.api_url = default_api_url()
    try:
        return args.run(args) or 0
    except LabError as error:
        print(f"\nError: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
