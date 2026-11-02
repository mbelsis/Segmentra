# Segmentra test lab

The test lab builds a small working environment with one command: three Docker machines, added to the inventory, protected by a sample firewall policy that is really deployed, with real traffic between them. Use it to try Segmentra, to demonstrate it, or to check a change, without any real servers.

```bash
python3 scripts/demo-lab.py up        # on Windows: python scripts\demo-lab.py up
```

> **For testing only.** The machines are privileged containers with a known user password, and the script adds hosts, a policy and a user to the Segmentra it runs against. Do not point it at a production Segmentra.

## Contents

- [What you need](#what-you-need)
- [Quick start](#quick-start)
- [What the lab contains](#what-the-lab-contains)
- [Architecture](#architecture)
- [The sample policy](#the-sample-policy)
- [What `up` does, step by step](#what-up-does-step-by-step)
- [Commands and options](#commands-and-options)
- [Things to try](#things-to-try)
- [What the lab changes](#what-the-lab-changes)
- [Limits of the lab](#limits-of-the-lab)
- [Troubleshooting](#troubleshooting)
- [Where the files are](#where-the-files-are)

## What you need

- A running Segmentra on the same computer (see [installation.md](installation.md)).
- Docker, running, with Linux containers.
- Python 3.8 or newer. The script uses only the standard library, so there is nothing to install.
- Internet access the first time, to download the base images and Debian packages.

## Quick start

**Production install** (`./install.sh --production`). The script finds the API and the admin password in `.env`:

```bash
python3 scripts/demo-lab.py up
```

**Development mode** (`./start.sh dev`). The API runs outside Docker, so deployments have to use the SSH executor:

```bash
python3 scripts/demo-lab.py up --set-executor-ssh
```

`--set-executor-ssh` changes a global setting that applies to every deployment, which is why you have to ask for it.

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

When you have finished:

```bash
python3 scripts/demo-lab.py down
```

## What the lab contains

**In Docker**

| Item | Name | Details |
|---|---|---|
| Images | `test-a`, `test-b`, `test-c` | The same Debian 12 image under three names |
| Containers | `test-a`, `test-b`, `test-c` | Addresses `.11`, `.12` and `.13` on the lab network |
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

Only port 22 is published, and only on `127.0.0.1`. Everything else stays inside the lab network. The script chooses the mode itself: if a container publishes the API's port, it is a Docker install.

### How the firewall sees the traffic

Each container has its own network stack, so its firewall rules are real and independent: `iptables` inside `test-b` decides what reaches `test-b`.

The sample traffic comes from real clients run inside the machines with `docker exec`. So `test-a -> test-b` is an actual packet leaving `test-a` and being judged by the firewall on `test-b`. The script tests what the service answers, not just whether a port is open: `ssh` must return the target's hostname, `telnet` must show a login prompt, and `curl` must return the target's page.

### How the logs reach Segmentra

```
  packet --> iptables rule with logging --> kernel log --> rsyslog in the machine
                                                                 |
       Peek at Logs / Policy Impact Analysis <-- SSH <-- /var/log/kern.log
```

Containers share one kernel, which creates two lab-only details:

- Kernels do not log firewall lines from containers by default. The script turns on `net.netfilter.nf_log_all_netns`, and `down` puts the old value back.
- The kernel log holds the lines of all three machines. Each machine's rsyslog keeps only its own: packets arriving for it, and packets it sends. That makes each machine's log look like a real server's.

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
7. **Runs the traffic** with no policy, to show that everything is open.
8. **Creates and approves the policy.** Segmentra requires a second person to approve a change, so the script switches on `demo-lab-approver`, approves as that user, and switches it off again.
9. **Deploys the policy** through the normal deployment flow, including the second approval for a deployment Segmentra rates high risk.
10. **Runs the traffic again** and compares every result with the policy. Any difference is marked `(!)`, and the script exits with an error.

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

### `status`

Shows whether the lab is set up, how it is connected, and the state and address of each machine.

### `down`

Accepts `--api-url`, `--username` and `--password`, like `up`.

| Option | Meaning |
|---|---|
| `--remove-images` | Also removes the images `test-a`, `test-b` and `test-c` |

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
| Tag `demo-lab` | Stays while the hosts use it |
| Deployments and audit log | Stay |

Running `up` again reuses the hosts and creates a new policy version. Nothing else changes: not the management network, and not the executor unless you pass `--set-executor-ssh`, which `down` does not undo.

## Limits of the lab

- **Not a real server.** Containers share a kernel and have no boot process, so a policy surviving a reboot, for example, is not tested here.
- **iptables only.** The machines use the iptables backend. nftables, firewalld and UFW are not part of the lab.
- **Hosts only.** Traffic is judged by the rules on the receiving host. Gateways and FORWARD rules have their own lab in `tests/ot-gateway-lab`.
- **Segmentra must be on the same computer** as Docker, because the containers need to reach it directly.
- **Windows** has not been tested yet. The script is written to work there, but it has only been run on macOS.

## Troubleshooting

| Message or symptom | What it means | What to do |
|---|---|---|
| `Docker is installed but not running` | The Docker daemon is not answering | Start Docker and try again |
| `Cannot reach Segmentra at ...` | The API is not running, or is on another port | Start Segmentra, or use `--api-url` |
| `Could not log in to Segmentra` | No password worked | Use `--username`, and `--password` or `SEGMENTRA_ADMIN_PASSWORD` |
| `Deployments currently use the ansible executor...` | Ansible cannot reach the machines from this setup | Add `--set-executor-ssh`, or change the executor under Admin |
| `A container called test-a already exists...` | Something of yours has that name, and the lab will not touch it | Rename or remove it |
| `Your inventory already has a host called test-a...` | A host of yours has that name, without the `demo-lab` tag | Rename it |
| `Could not create the network on ...` | The range overlaps another network | Choose another with `--subnet` |
| `Host key verification failed` | The image was rebuilt from scratch, so a machine has a new host key | Remove the old entry from the `known_hosts` of the user running the API, then run `up` again |
| A deployment fails with `ansible_failed` and the API cannot use Docker | The API has no access to the Docker socket | Check `DOCKER_GID` in `.env`. The installer normally sets it |
| Results marked `(!)` in `traffic` | A result differs from the sample policy | Expected during a log-only test or after you change the policy. Otherwise, check the host's **Active Rules** |
| Peek at Logs is empty | The traffic has not run yet, or the policy was deployed before default-deny logging existed | Run `traffic`, then **Refresh**. Otherwise run `up` to deploy again |
| `could not turn on container firewall logging` | The kernel setting could not be changed | The policy still works, but logs may stay empty. Check that Docker can run privileged containers |
| `down` warns that Segmentra was not cleaned up | Segmentra could not be reached | The machines are still removed. Disable the hosts and archive the policy by hand |

## Where the files are

| File | Purpose |
|---|---|
| `scripts/demo-lab.py` | The script |
| `infra/demo-lab/Dockerfile` | The machines' image |
| `infra/demo-lab/entrypoint.sh` | What starts inside each machine: accounts, services, rsyslog filter |
| `.demo-lab.json` | The running lab's state, not in git |
