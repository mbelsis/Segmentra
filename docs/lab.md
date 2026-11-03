# Segmentra test lab

The test lab builds a small working environment with one command: three Docker machines, added to the inventory, protected by a sample firewall policy that is really deployed, with real traffic between them, and a syslog collector receiving Segmentra's Audit Log as a sample SIEM. Use it to try Segmentra, to demonstrate it, or to check a change, without any real servers.

**Lab or demo data?** The [demo data](../README.md#demo-data-optional) (`npm run db:demo`) fills the UI with sample hosts, policies, OT devices and deployments, but nothing behind them is real, so nothing can be deployed or tested. The lab has fewer records, but its firewalls and traffic are real. To have both, load the demo data first, because its loader refuses a database that already has other hosts.

Segmentra has to be running first. The [quick start](#quick-start) gives the exact commands for macOS, Linux and Windows.

> **For testing only.** The machines are privileged containers with a known user password, and the script adds hosts, a policy and a user to the Segmentra it runs against. Do not point it at a production Segmentra.

## Contents

- [What you need](#what-you-need)
- [Quick start](#quick-start)
- [What the lab contains](#what-the-lab-contains)
- [Architecture](#architecture)
- [The sample policy](#the-sample-policy)
- [What `up` does, step by step](#what-up-does-step-by-step)
- [Commands and options](#commands-and-options)
- [The sample SIEM](#the-sample-siem)
- [Things to try](#things-to-try)
- [What the lab changes](#what-the-lab-changes)
- [The IoT lab](#the-iot-lab)
- [Limits of the lab](#limits-of-the-lab)
- [Troubleshooting](#troubleshooting)
- [Where the files are](#where-the-files-are)

## What you need

- Segmentra on the same computer, started as shown in the [quick start](#quick-start). The full setup is in [installation.md](installation.md).
- Docker, running, with Linux containers.
- Python 3.8 or newer: `python3` on macOS and Linux, `python` or `py` on Windows. The script uses only the standard library, so there is nothing else to install.
- Internet access the first time, to download the base images and Debian packages.

## Quick start

### 1. Start Segmentra in development mode

From the repository folder:

| System | Command | What happens next |
|---|---|---|
| macOS or Linux | `./start.sh dev` | Keeps running in this terminal. Leave it open and use a second terminal for the lab |
| Windows | `start.bat dev` in Command Prompt, `.\start.bat dev` in PowerShell | Opens the API and the UI in their own windows. Leave those open and carry on in the first one |

Wait until the API answers. The address http://localhost:8080/api/health should open in a browser. The UI is at http://localhost:5173, and the development login is `admin` / `admin123`.

### 2. Start the lab

**macOS or Linux** (in a second terminal, in the repository folder):

```bash
python3 scripts/demo-lab.py up --set-executor-ssh
```

**Windows** (Command Prompt or PowerShell, in the repository folder):

```bat
python scripts\demo-lab.py up --set-executor-ssh
```

If Windows says `python` was not found, use `py` instead: `py scripts\demo-lab.py up --set-executor-ssh`.

`--set-executor-ssh` is needed because the API runs outside Docker, so Ansible cannot reach the machines. It changes the deployment setting for all deployments on this install, and `down` does not undo it. If the setting is already SSH, the flag changes nothing.

### Using a production install instead

If you installed with `./install.sh --production` or `.\install.ps1 --production`, Segmentra is already running in Docker, and the Ansible runner can reach the machines, so you do not need the flag. The script finds the API and the admin password in `.env`:

```bash
python3 scripts/demo-lab.py up        # Windows: python scripts\demo-lab.py up
```

### 3. See the result

The first run takes a minute or two, because it builds the image. It ends with the result of the traffic and a line saying whether it matches the policy:

```
After the policy
  from    to      ping          ssh           telnet        curl
  test-a  test-b  ok            ok            blocked       ok
  test-a  test-c  ok            ok            blocked       ok
  test-b  test-a  blocked       blocked       blocked       ok
  test-b  test-c  blocked       blocked       blocked       ok
  test-c  test-a  blocked       blocked       ok            blocked
  test-c  test-b  blocked       blocked       ok            blocked

Ready. Every result matches the policy.
```

When you have finished, remove the lab:

```bash
python3 scripts/demo-lab.py down --remove-images        # Windows: python scripts\demo-lab.py down --remove-images
```

This removes the machines, the collector, the network and the lab's images. Leave out `--remove-images` to keep the images, so the next `up` starts faster.

The rest of this guide writes commands the macOS and Linux way. On Windows, replace `python3 scripts/demo-lab.py` with `python scripts\demo-lab.py`.

To stop Segmentra afterwards: on macOS or Linux, press Ctrl+C in its terminal. On Windows, close the API and UI windows. The database keeps running in Docker until you run `docker compose down`.

## What the lab contains

**In Docker**

| Item | Name | Details |
|---|---|---|
| Images | `test-a`, `test-b`, `test-c`, `test-syslog` | The same Debian 12 image under four names |
| Containers | `test-a`, `test-b`, `test-c` | Addresses `.11`, `.12` and `.13` on the lab network |
| Container | `test-syslog` | The sample SIEM, address `.20`, listening for syslog on port 514 over TCP and UDP |
| Network | `segmentra-demo-lab` | `172.28.77.0/24` by default |

**Services on every machine**

| Service | Port | Used for |
|---|---|---|
| SSH | 22 | Segmentra's management login (account `segmentra`, key only, passwordless sudo) |
| SSH | 2222 | The sample `ssh` traffic (account `demo`, password `demo`, no sudo) |
| Telnet | 23 | The sample `telnet` traffic |
| Web page | 80 | The sample `curl` traffic; the page says `Hello from <machine>` |
| rsyslog | | Reads the kernel log, where firewall log lines land |

**In Segmentra**

| Item | Name |
|---|---|
| Hosts | `test-a`, `test-b`, `test-c`, using the iptables backend |
| Tag | `demo-lab` |
| SSH credential | `demo-lab-credential`, scoped to the tag, so it is never chosen for any other host |
| Policy set | `Demo lab policy`, applied to the three hosts |
| User | `demo-lab-approver`, switched off except while approving |
| Integrations | `demo-lab-siem-tcp` and `demo-lab-siem-udp`, under **Integrations**, both pointing at `test-syslog` |

## Architecture

### Production install: the API runs in Docker

The script connects the API and the Ansible runner to the lab network, so they reach the machines directly on port 22.

```
  Your computer
  +----------------------------------------------------------------------------+
  |  scripts/demo-lab.py                                                       |
  |     |  HTTP (127.0.0.1:8080)             |  docker exec (sample traffic)   |
  |     v                                    |                                 |
  |  +-----------------+  +----------------+ |                                 |
  |  | segmentra-app   |  | ansible-runner | |                                 |
  |  | (API)           |  |                | |                                 |
  |  +--------+--------+  +-------+--------+ |                                 |
  |           |   SSH, port 22    |          |                                 |
  |  =========+===================+==========|===== segmentra-demo-lab ======  |
  |           |                   |          |      172.28.77.0/24             |
  |     +-----+------+   +--------+---+   +--+---------+                       |
  |     |  test-a    |   |  test-b    |   |  test-c    |                       |
  |     |  .11       |<->|  .12       |<->|  .13       |                       |
  |     +------------+   +------------+   +------------+                       |
  |           ping, ssh (2222), telnet (23), curl (80)                         |
  +----------------------------------------------------------------------------+
```

### Development mode: the API runs outside Docker

On Docker Desktop your computer cannot reach container addresses directly. So each machine publishes its management port on `127.0.0.1`, and the inventory uses those ports:

| Machine | Address in the inventory |
|---|---|
| `test-a` | `127.0.0.1`, port 22201 |
| `test-b` | `127.0.0.1`, port 22202 |
| `test-c` | `127.0.0.1`, port 22203 |

The collector is published too, on `127.0.0.1:15514`, so the API can reach it. Nothing is published beyond `127.0.0.1`, and everything else stays inside the lab network. The script chooses the mode itself: if a container publishes the API's port, it is a Docker install.

### How the firewall sees the traffic

Each container has its own network stack, so its firewall rules are real and independent: `iptables` inside `test-b` decides what reaches `test-b`.

The sample traffic comes from real clients run inside the machines with `docker exec`. So `test-a -> test-b` is an actual packet leaving `test-a` and being judged by the firewall on `test-b`. The script tests what the service answers, not just whether a port is open: `ssh` must return the target's hostname, `telnet` must show a login prompt, and `curl` must return the target's page.

### How the logs reach Segmentra

```
  packet --> iptables rule with logging --> kernel log --> kmsg-forward.py --> rsyslog
                                                                                 |
       Peek at Logs / Policy Impact Analysis <-- SSH <-- /var/log/kern.log <-----+
```

Containers share one kernel, which creates two lab-only details:

- Kernels do not log firewall lines from containers by default. The script turns on `net.netfilter.nf_log_all_netns`, and `down` puts the old value back.
- The kernel log holds the lines of all three machines. A small program on each machine, `kmsg-forward.py`, passes on only its own: packets arriving for it, and packets it sends. That makes each machine's log look like a real server's. It reads `/dev/kmsg` because rsyslog's usual kernel input reads `/proc/kmsg`, which gives each line to only one reader, so the machines would steal each other's lines.

## The sample policy

The policy is enforced on all three machines, so what matters is who the traffic comes from.

| Order | Action | Protocol and port | From | Comment in the logs | Why it is there |
|---|---|---|---|---|---|
| 5 | ALLOW | tcp/22 | Lab network | none (logging off) | Keeps Segmentra's management login working |
| 10 | ALLOW | icmp | `test-a` | `ping-a` | Only `test-a` may ping |
| 20 | ALLOW | tcp/2222 | `test-a` | `ssh-a` | Only `test-a` may use ssh |
| 30 | ALLOW | tcp/80 | `test-a` | `web-a` | The web page is open to `test-a`... |
| 31 | ALLOW | tcp/80 | `test-b` | `web-b` | ...and to `test-b` |
| 40 | ALLOW | tcp/23 | `test-c` | `telnet-c` | Only `test-c` may use telnet |
| 50 | DENY | tcp/23 | `test-b` | `no-telnet` | An explicit denial, to see in the logs |
| | deny | everything else | anyone | `default` | The default deny |

That gives this result:

| Traffic | Allowed from | Blocked from |
|---|---|---|
| ping | `test-a` | `test-b`, `test-c` |
| ssh (port 2222) | `test-a` | `test-b`, `test-c` |
| telnet | `test-c` | `test-b` (rule 50), `test-a` (default deny) |
| curl | `test-a`, `test-b` | `test-c` (default deny) |

The rules log at a limited rate of 5 lines per second per rule, with short bursts of up to 10. The default deny is limited the same way, so the logs show that a kind of traffic was blocked, not necessarily every packet.

**Why ssh uses port 2222.** With no management network configured, Segmentra keeps port 22 open from everywhere, so that a host can never be locked out. A policy cannot block it, and changing that global setting could affect your other hosts. A separate port lets the policy decide without touching anything else.

## What `up` does, step by step

1. **Checks.** Docker is running, Segmentra answers, the login works, and no existing host called `test-a`, `test-b` or `test-c` would be overwritten.
2. **Chooses the mode.** Works out whether the API runs in Docker, and whether the current executor can reach the machines. If not, it stops here, before creating anything.
3. **Builds and starts the machines.** Image, network and containers, using a newly generated SSH key.
4. **Connects the API** and the Ansible runner to the lab network (production install only).
5. **Turns on container firewall logging** (`nf_log_all_netns`).
6. **Fills the inventory.** Tag, credential and hosts.
7. **Connects the sample SIEM.** Starts `test-syslog` and registers it as an integration over each protocol.
8. **Runs the traffic** with no policy, to show that everything is open.
9. **Creates and approves the policy.** Segmentra requires a second person to approve a change, so the script switches on `demo-lab-approver`, approves as that user, and switches it off again.
10. **Deploys the policy** through the normal deployment flow, including the second approval for a deployment Segmentra rates high risk, and the readiness check every host goes through before its first policy. The script accepts the check's note that rules are lost on reboot, because containers have no boot to survive.
11. **Runs the traffic again** and compares every result with the policy. Any difference is marked `(!)`, and the script exits with an error.
12. **Checks the sample SIEM.** Sends a connectivity test over each protocol, and confirms that it and the deployment's Audit Log entries arrived over both.

`up` is safe to run again. It reuses what exists and deploys the policy again.

## Commands and options

### `up`

| Option | Meaning |
|---|---|
| `--api-url URL` | The Segmentra API. Default: `http://127.0.0.1:<API_PORT from .env, or 8080>/api` |
| `--username NAME` | Segmentra admin user. Default: `admin` |
| `--password PASSWORD` | Its password (see below) |
| `--subnet CIDR` | Network for the machines, a free /24. Default: `172.28.77.0/24` |
| `--set-executor-ssh` | Switches deployments to the SSH executor. A global setting, needed only when Ansible cannot reach the machines |

The password is taken from the first of these that works: `--password`, the environment variable `SEGMENTRA_ADMIN_PASSWORD`, `.env`, the development default. If none works, the script asks.

### `traffic`

Runs the sample traffic and checks it against the policy. Exits with 1 if any result differs.

| Option | Meaning |
|---|---|
| `--repeat N` | How many rounds. Default: 1 |
| `--interval SECONDS` | Time between rounds. Default: 10 |

### `siem`

Shows how many messages the sample SIEM received over each protocol, and the newest ones.

| Option | Meaning |
|---|---|
| `--last N` | How many of the newest messages to show. Default: 15 |
| `--by-action` | Also counts the messages per action |

### `status`

Shows whether the lab is set up, how it is connected, and the state and address of each machine and the collector.

### `down`

Accepts `--api-url`, `--username` and `--password`, like `up`.

| Option | Meaning |
|---|---|
| `--remove-images` | Also removes the images `test-a`, `test-b`, `test-c` and `test-syslog` |

## The sample SIEM

`test-syslog` stands in for a real SIEM. It is rsyslog, set to write every message exactly as it arrived, one file per protocol: `/var/log/siem/tcp.log` and `/var/log/siem/udp.log`. Segmentra treats it like any other syslog destination, so what you see here is what a real SIEM would get.

```bash
python3 scripts/demo-lab.py siem --by-action
```

**What it receives: the Audit Log.** Every entry, such as a policy approved, a deployment started or a user changed, goes out as one RFC 5424 message:

```
<110>1 2026-11-03T06:29:45.123Z segmentra segmentra-audit - - [audit@segmentra action="HOST_CREATE" actor="admin" entityType="host" entityId="242d2bb0-..."] HOST_CREATE by admin on host:242d2bb0-...
```

**What it does not receive: firewall logs.** The accepted and denied lines in Peek at Logs stay on each host. Segmentra has no firewall log forwarding yet.

Good to know:

- **Your other integrations are unaffected.** Every enabled SIEM integration gets every message, so a real SIEM you have configured keeps working. The sample one just receives the same entries.
- **It also receives the recent past.** When a SIEM is first enabled, Audit Log entries from the last 60 minutes that were never forwarded are sent too, so the first count can be higher than what the lab itself did.
- **UDP cannot confirm delivery.** That is how UDP works, and why the lab tests both. In **Integrations**, the **Test** button sends a test message and says so for UDP.
- **If the collector is down,** events are kept and sent again within about a minute of it returning, as long as they are less than 60 minutes old and no other SIEM accepted them. Try it with `docker stop test-syslog`, then `docker start test-syslog`.

## Things to try

### See accepted and denied traffic

1. Run `python3 scripts/demo-lab.py traffic`.
2. In Segmentra, open **Inventory**, then **Actions > Peek at Logs** on `test-b`.
3. Use the **Accepted** and **Denied** filters. The **Rule** column shows which rule decided, or `default` for the default deny.

Compare `test-b` with `test-c`. Telnet from `test-b` appears on `test-c` as denied by `no-telnet`, and ping from `test-c` appears on `test-b` as denied by `default`.

### Test a policy before enforcing it

1. Open **Policy Impact Analysis** and start a test with `Demo lab policy` on `test-b`.
2. Run `python3 scripts/demo-lab.py traffic`. Results to `test-b` that the policy normally blocks now succeed and are marked `(!)`, and the command exits with 1. That is correct: a log-only test blocks nothing.
3. Click **Stop & Collect**, then **Analyze**, to see which flows the policy covers and which it would block.

### Run a test with traffic flowing

Keep traffic going while you work in the UI:

```bash
python3 scripts/demo-lab.py traffic --repeat 20 --interval 30
```

### Change the policy

Create a new version of `Demo lab policy` in the UI, for example allowing ping from `test-b`, then have it approved and deploy it. Remember that `traffic` always compares with the original sample policy in the script, so your change will show as `(!)`.

### See the Audit Log reach the SIEM

1. In Segmentra, change something: approve a policy, or add a tag.
2. Run `python3 scripts/demo-lab.py siem --last 5`. The action is there within a few seconds.
3. Open **Integrations** to see `demo-lab-siem-tcp` and `demo-lab-siem-udp`, and press **Test** on one.

### Look at what is on a machine

```bash
docker exec test-b iptables-save | grep SEGMENTRA      # the deployed rules
docker exec -it test-b bash                            # a shell on the machine
```

Also useful: **Inventory > Actions > Active Rules** shows the rules a host should have next to the ones it actually has. Remove a rule by hand and **Check Compliance** reports the drift.

## What the lab changes

**On your computer**

- Creates `.demo-lab.json` in the repository folder, holding the lab's private SSH key. It is ignored by git, and readable only by you on macOS and Linux. `down` deletes it.
- In development mode, the machines' host keys are added to the `known_hosts` of the user running the API. `down` does not remove these lines.

**In Docker**

- Creates the images, containers and network listed above.
- Connects the API and Ansible runner containers to the lab network. `down` disconnects them.
- Sets `net.netfilter.nf_log_all_netns=1` on the kernel that runs your containers. On Linux that is your computer's own kernel. `down` restores the previous value.

**In Segmentra**

`down` removes what it can. Segmentra keeps deployment history on purpose, so some items stay:

| Item | After `down` |
|---|---|
| SSH credential | Deleted |
| Running policy tests | Stopped |
| Hosts | Disabled, because they have deployment history |
| Policy set | Archived, because approved versions cannot be deleted |
| User `demo-lab-approver` | Stays, switched off. Deleting a user erases the record of what they approved |
| SIEM integrations | Deleted |
| Tag `demo-lab` | Stays while the hosts use it |
| Deployments and audit log | Stay |

Running `up` again reuses the hosts and creates a new policy version. Nothing else changes: not the management network, and not the executor unless you pass `--set-executor-ssh`, which `down` does not undo.

## The IoT lab

A second lab, for what cannot run a firewall of its own: a Linux gateway between an IT and an OT network, with simulated industrial devices behind it. The gateway filters what it routes to them. It can run next to the base lab.

```bash
python3 scripts/demo-lab.py up --lab iot          # add --set-executor-ssh when the API runs outside Docker
python3 scripts/demo-lab.py traffic --lab iot     # real requests, compared with the policy
python3 scripts/demo-lab.py check --lab iot       # test Segmentra's IoT features against the lab
python3 scripts/demo-lab.py status --lab iot
python3 scripts/demo-lab.py down --lab iot        # --remove-images also removes the image
```

On Windows, write these as `python scripts\demo-lab.py up --lab iot`, and so on.

```
 IT network 172.28.78.0/24                               OT network 172.28.79.0/24
 iot-hmi     .50                 iot-gw                  iot-plc      .11  Modbus 502, S7 102
 iot-eng     .51  <--------->  .2      .2  <--------->   iot-rtu      .12  DNP3 20000, Modbus 502
 iot-office  .52               routes and filters        iot-sensor   .13  MQTT 1883
                                                         iot-camera   .14  RTSP 554, HTTP 80
                                                         iot-printer  .15  JetDirect 9100, not registered
```

The clients reach the OT network through the gateway, and the devices use it as their default route, so all traffic between the networks crosses its firewall. A passing test means a device answered a real protocol request, not just that a port was open.

Only `iot-gw` joins the inventory as a host, with the system tag `iot-gateway`. Four devices are registered as IoT assets assigned to it. The printer is left out on purpose.

### The sample policy

| Device and service | hmi | eng | office |
|---|---|---|---|
| plc, Modbus | allowed | blocked | blocked |
| plc, S7 | blocked | allowed | blocked |
| rtu, DNP3 | allowed | blocked | blocked |
| rtu, Modbus | blocked by an explicit rule | same | same |
| sensor, MQTT | allowed | allowed | blocked |
| camera, RTSP | allowed | blocked | blocked |
| camera, HTTP | blocked | blocked | allowed |
| printer, JetDirect | open | open | open |

Three more flows are checked. Ping from the HMI to the PLC is blocked. A PLC calling into the IT network is blocked by an explicit rule, because the default deny only covers traffic *to* a protected device. PLC to RTU works, for the reason below.

### What it shows

- **Registering is what protects a device.** The printer stays open to everyone, because a gateway only default-denies devices assigned to it.
- **A gateway only filters what it routes.** PLC to RTU stays on the OT network and never reaches `iot-gw`. Separating devices on one network takes VLANs or a switch.
- **Discovery lists both sides of the gateway.** On **OT/IoT > Discovery**, the printer appears as new, and so do the IT clients and, when the API runs in Docker, the API container, because all of them are in the gateway's neighbour table.

### What `check` tests

`check` changes the lab for about two minutes and restores it. It covers:

- traffic against the policy, the readiness check and compliance
- **Coverage**, including cleartext protocols and the explicit deny
- **Discovery**, with registered devices recognised and the printer found
- **Peek at Logs**, with allowed, default-deny and explicit-deny lines for routed traffic
- **Drift**: it removes a rule by hand, confirms the HMI really lost access, then redeploys
- **Policy Impact Analysis** in log-only mode, on routed flows
- taking a device off the gateway, redeploying, and putting it back

`npm run test:lab:iot` runs `up`, `check`, `traffic` and `down` on a disposable Segmentra (API on port 18083), then verifies that nothing is left behind. It refuses to run while the same lab is up from this folder, because the container names are fixed. It has passed on macOS with the API in Docker using SSH, with the API outside Docker using SSH, and on a production install using Ansible.

### What it adds and leaves behind

It uses the networks `segmentra-iot-it` and `segmentra-iot-ot` (`--subnet` and `--ot-subnet` choose other free ranges), the image `segmentra-lab-machine`, the tag `demo-lab-iot`, a credential scoped to that tag, the state file `.demo-lab-iot.json`, and port 22211 on 127.0.0.1 when the API runs outside Docker. After `down`, Segmentra keeps its history, so `iot-gw` stays disabled and `IoT lab policy` stays archived; `up` reuses them. The assets and the credential are removed.

### Limits

The devices are small simulators that answer one request. They test firewall rules, not how real equipment behaves, and they do not run the protocols' full logic. All machines share one kernel, and the gateway uses iptables only.

## Limits of the lab

- **Not a real server.** Containers share a kernel and have no boot process, so a policy surviving a reboot, for example, is not tested here.
- **iptables only.** The machines use the iptables backend. nftables, firewalld and UFW are not part of the lab.
- **Hosts only.** Traffic is judged by the rules on the receiving host. Gateways and FORWARD rules are in [the IoT lab](#the-iot-lab).
- **Segmentra must be on the same computer** as Docker, because the containers need to reach it directly.
- **Audit Log only.** The sample SIEM shows that the Audit Log is forwarded. Firewall log lines are not forwarded at all.
- **Windows** has not been tested yet. The script is written to work there, but it has only been run on macOS.

## Troubleshooting

| Message or symptom | What it means | What to do |
|---|---|---|
| `command not found: python` on macOS or Linux | The command there is `python3` | Use `python3 scripts/demo-lab.py ...` |
| `can't open file ... scriptsdemo-lab.py` | The Windows backslash was used on macOS or Linux | Use a forward slash: `scripts/demo-lab.py` |
| `Docker is installed but not running` | The Docker daemon is not answering | Start Docker and try again |
| `Cannot reach Segmentra at ...` | The API is not running, or is on another port | Start it with `./start.sh dev` or `start.bat dev`, or use `--api-url` |
| `Could not log in to Segmentra` | No password worked | Use `--username`, and `--password` or `SEGMENTRA_ADMIN_PASSWORD` |
| `Deployments currently use the ansible executor...` | Ansible cannot reach the machines from this setup | Add `--set-executor-ssh`, or change the executor under Admin |
| `A container called test-a already exists...` | Something of yours has that name, and the lab will not touch it | Rename or remove it |
| `Your inventory already has a host called test-a...` | A host of yours has that name, without the `demo-lab` tag | Rename it |
| `The sample SIEM did not receive the events over: ...` | The API could not deliver to the collector | Check the API's log for `[SIEM]` lines, and that `test-syslog` is running with `status` |
| Nothing under **Integrations** | The lab is not up on this Segmentra, or you ran `down`, which removes them | Run `up` against the Segmentra you are looking at |
| `Could not create the network on ...` | The range overlaps another network | Choose another with `--subnet` |
| `Host key verification failed` | The image was rebuilt from scratch, so a machine has a new host key | Remove the old entry from the `known_hosts` of the user running the API, then run `up` again |
| A deployment fails with `ansible_failed` and the API cannot use Docker | The API has no access to the Docker socket | Check `DOCKER_GID` in `.env`. The installer normally sets it |
| Results marked `(!)` in `traffic` | A result differs from the sample policy | Expected during a log-only test or after you change the policy. Otherwise, check the host's **Active Rules** |
| `traffic` shows results marked `(!)` after Docker restarted | Containers have no boot process: each machine clears its firewall when it starts, and the kernel logging setting is reset | Run `up` again (with the same `--lab`) to deploy the policy and turn logging back on |
| Peek at Logs is empty | The traffic has not run yet, or the policy was deployed before default-deny logging existed | Run `traffic`, then **Refresh**. Otherwise run `up` to deploy again |
| `could not turn on container firewall logging` | The kernel setting could not be changed | The policy still works, but logs may stay empty. Check that Docker can run privileged containers |
| `down` warns that Segmentra was not cleaned up | Segmentra could not be reached | The machines are still removed. Disable the hosts and archive the policy by hand |

## Where the files are

| File | Purpose |
|---|---|
| `scripts/demo-lab.py` | The command line |
| `scripts/demolab/` | The labs: `common.py` is shared, `base.py` and `iot.py` are one lab each |
| `tests/labs/` | Runs a lab from start to finish on a disposable Segmentra |
| `infra/demo-lab/iot-device.py` | The simulated devices and the client that probes them |
| `infra/demo-lab/Dockerfile` | The machines' image |
| `infra/demo-lab/entrypoint.sh` | What starts inside each machine: accounts and services |
| `infra/demo-lab/kmsg-forward.py` | Passes each machine's own firewall lines to rsyslog |
| `infra/demo-lab/syslog-receiver.sh` | Runs the sample SIEM in `test-syslog` |
| `.demo-lab.json`, `.demo-lab-iot.json` | Each running lab's state, not in git |
