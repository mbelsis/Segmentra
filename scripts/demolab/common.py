"""What every lab needs: Docker, the Segmentra API, approvals, deployments and saved state."""
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

ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = ROOT / "infra" / "demo-lab"
LABEL = "segmentra.demo-lab"
APPROVER_NAME = "demo-lab-approver"
# Containers have no boot to survive, so the readiness note about rules being lost on reboot does not matter here.
START_BODY = {"acceptReadinessNotes": True}
NF_LOG_SYSCTL = "/proc/sys/net/netfilter/nf_log_all_netns"
SYSCTL_IMAGE = "alpine:3.20"
STATE_GLOB = ".demo-lab*.json"


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


def refuse_foreign(kind, name):
    if labelled(kind, name) is False:
        raise LabError(f"A {kind} called {name} already exists and was not created by this script. Remove or rename it first.")


def create_network(name, subnet):
    if docker("network", "inspect", name, check=False).returncode == 0:
        return
    done = docker("network", "create", "--subnet", subnet, "--label", f"{LABEL}=1", name, check=False)
    if done.returncode != 0:
        raise LabError(f"Could not create the network on {subnet}: {done.stderr}\nPick a free range with --subnet.")


def generate_ssh_key(image):
    """Made inside the lab's own image, so the computer running this script needs no ssh tools."""
    script = "ssh-keygen -q -t ed25519 -N '' -C demo-lab -f /tmp/k && cat /tmp/k.pub && cat /tmp/k"
    done = docker("run", "--rm", "--entrypoint", "sh", image, "-c", script)
    public, _, private = done.stdout.partition("\n")
    return public.strip(), private.strip() + "\n"


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


def connect_to_network(names, network):
    for name in names:
        done = docker("network", "connect", network, name, check=False)
        if done.returncode != 0 and "already exists" not in done.stderr:
            raise LabError(f"Could not connect {name} to the lab network: {done.stderr}")


def enable_container_firewall_logs(state, state_file):
    """Kernels only log firewall lines from containers with this setting. The old value is put back by the last `down`."""
    script = f"cat {NF_LOG_SYSCTL} 2>/dev/null; echo 1 > {NF_LOG_SYSCTL}"
    done = docker("run", "--rm", "--privileged", "--network", "host", SYSCTL_IMAGE, "sh", "-c", script, check=False)
    if done.returncode != 0:
        say("  Warning: could not turn on container firewall logging, so Peek at Logs may stay empty.")
    elif "nf_log_previous" not in state:
        state["nf_log_previous"] = done.stdout.strip() or None
        save_state(state_file, state)


def restore_container_firewall_logs(state, state_file):
    """The setting is one per kernel, so a lab that is still up inherits the original value instead."""
    previous = state.get("nf_log_previous")
    others = [p for p in ROOT.glob(STATE_GLOB) if p != state_file]
    if others:
        # Whichever lab came first holds the real original value, and only that one is 0 when it was off.
        remaining = json.loads(others[0].read_text(encoding="utf-8"))
        if previous == "0" or "nf_log_previous" not in remaining:
            remaining["nf_log_previous"] = previous
            save_state(others[0], remaining)
        return
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
            with urllib.request.urlopen(request, timeout=120) as response:
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


def default_api_url():
    return f"http://127.0.0.1:{read_dotenv().get('API_PORT') or 8080}/api"


def is_local(url):
    return urllib.parse.urlparse(url).hostname in ("127.0.0.1", "localhost", "::1")


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


def has_tag(host, tag_name):
    return any((t.get("name") if isinstance(t, dict) else t) == tag_name for t in host.get("tags") or [])


def find_tag(api, name):
    for tag in api.get("/tags").get("tags", []):
        if tag["name"] == name:
            return tag
    return None


def ensure_tag(api, name):
    tag = find_tag(api, name)
    return tag["id"] if tag else api.post("/tags", {"name": name, "description": "Created by scripts/demo-lab.py"})["tag"]["id"]


def find_credential(api, name):
    for credential in api.get("/ssh-credentials").get("sshCredentials", []):
        if credential["name"] == name:
            return credential
    return None


def ensure_credential(api, name, tag_id, private_key):
    """Scoped to the lab's tag, so it is never chosen for any other host."""
    body = {"name": name, "username": "segmentra", "scopeType": "TAG", "scopeId": tag_id, "priority": 0, "sudoMode": "NOPASSWD"}
    existing = find_credential(api, name)
    if existing:
        # A stored key cannot be replaced through an update.
        api.request("DELETE", f"/ssh-credentials/{existing['id']}")
    api.post("/ssh-credentials", {**body, "authMethod": "KEY", "privateKeyPem": private_key})


def find_policy_set(api, name):
    for policy in api.get("/policy-sets").get("policySets", []):
        if policy["name"] == name:
            return policy
    return None


def versions_of(api, policy_set_id):
    return api.get(f"/policy-sets/{policy_set_id}/versions").get("versions", [])


def ensure_approved_version(api, policy_name, description, host_ids, rules):
    """The newest usable version of the policy, or a new one with `rules`, submitted and approved."""
    policy = find_policy_set(api, policy_name)
    if policy:
        usable = [v for v in versions_of(api, policy["id"]) if v["status"] in ("APPROVED", "DEPLOYED")]
        if usable:
            return usable[0]["id"]
        policy_id = policy["id"]
    else:
        policy_id = api.post("/policy-sets", {
            "name": policy_name, "description": description, "scopeType": "HOST_LIST", "hostIds": list(host_ids.values()),
        })["policySet"]["id"]
    version_id = api.post(f"/policy-sets/{policy_id}/versions", {"changeSummary": "Sample rules", "interfaceScopeType": "ALL_INTERFACES"})["version"]["id"]
    for rule in rules():
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


def stop_sessions(api, host):
    """A log-only session left running would keep trying to restore a machine that no longer exists."""
    for path, finish in (("/policy-test/sessions", "stop"), ("/troubleshoot/audit/sessions", "restore")):
        status, data = api.request("GET", f"{path}?hostId={host['id']}", ok=(200, 400, 404))
        if status != 200:
            continue
        for session in data.get("sessions", []):
            if session.get("host_id") == host["id"] and session.get("status") == "RUNNING":
                api.request("POST", f"{path}/{session['id']}/{finish}", {}, ok=(200, 400, 404, 409, 500))


def remove_policy_set(api, name):
    """Removes what it can. Returns True when the policy set is gone; Segmentra keeps it when deployments used it."""
    policy = find_policy_set(api, name)
    if not policy:
        return True
    for version in versions_of(api, policy["id"]):
        if version["status"] in ("APPROVED", "DEPLOYED", "PENDING_APPROVAL"):
            api.request("POST", f"/policy-versions/{version['id']}/archive", {}, ok=(200, 201, 400, 404, 409))
        elif version["status"] in ("DRAFT", "REJECTED"):
            api.request("DELETE", f"/policy-versions/{version['id']}", ok=(200, 204, 400, 404, 409))
    api.request("DELETE", f"/policy-sets/{policy['id']}", ok=(200, 204, 400, 404, 409))
    return find_policy_set(api, name) is None


def remove_host(api, host):
    """Returns True when the host is gone; a host with deployment history is disabled instead."""
    status, _ = api.request("DELETE", f"/hosts/{host['id']}", ok=(200, 204, 400, 404, 409))
    if status in (200, 204):
        return True
    api.request("PUT", f"/hosts/{host['id']}", {"enabled": False})
    return False


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


# --- State -----------------------------------------------------------------------------------------

def load_state(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


def save_state(path, state):
    path.touch(mode=0o600)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
