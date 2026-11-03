#!/usr/bin/env python3
"""Build a test environment for Segmentra with one command.

  python3 scripts/demo-lab.py up             three Docker machines, inventory, a sample policy, deployed
  python3 scripts/demo-lab.py up --lab iot   an IoT/OT gateway, IT clients and simulated devices behind it
  python3 scripts/demo-lab.py traffic        real traffic, compared with the policy
  python3 scripts/demo-lab.py check --lab iot   test Segmentra's features against the lab
  python3 scripts/demo-lab.py siem           what the sample SIEM received (base lab)
  python3 scripts/demo-lab.py status         what exists right now
  python3 scripts/demo-lab.py down           remove it again

Every command takes --lab (base, iot; default base). Labs can run side by side.

Needs Python 3.8+, Docker and a running Segmentra (./install.sh --production or ./start.sh dev).
Uses only the Python standard library. Run with --help on a command for its options.

Everything is created through Segmentra's normal API, and nothing global is changed unless you pass
--set-executor-ssh. FOR TESTING ONLY: the machines are containers with known passwords, some privileged.
"""
import argparse
import sys

sys.dont_write_bytecode = True  # no __pycache__ folder in the repository

from demolab import base, iot  # noqa: E402
from demolab.common import LabError, default_api_url  # noqa: E402

LABS = {"base": base, "iot": iot}


def run_lab_command(args):
    lab = LABS[args.lab]
    command = getattr(lab, f"cmd_{args.command}", None)
    if command is None:
        raise LabError(f"The {args.lab} lab has no {args.command} command.")
    return command(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    which = argparse.ArgumentParser(add_help=False)
    which.add_argument("--lab", choices=sorted(LABS), default="base", help="which lab (default: %(default)s)")
    common = argparse.ArgumentParser(add_help=False, parents=[which])
    common.add_argument("--api-url", help="Segmentra API (default: http://127.0.0.1:<API_PORT from .env, or 8080>/api)")
    common.add_argument("--username", default="admin", help="Segmentra admin user (default: admin)")
    common.add_argument("--password", help="its password (default: SEGMENTRA_ADMIN_PASSWORD, .env, the dev default, then it asks)")
    commands = parser.add_subparsers(dest="command", required=True)

    up = commands.add_parser("up", parents=[common], help="create everything and deploy the sample policy")
    up.add_argument("--subnet", help="network for the machines; the IT network in the iot lab (a free /24, defaults: base 172.28.77.0/24, iot 172.28.78.0/24)")
    up.add_argument("--ot-subnet", help="iot lab: the OT network behind the gateway (a free /24, default: 172.28.79.0/24)")
    up.add_argument("--set-executor-ssh", action="store_true", help="switch deployments to the SSH executor; a global setting, only needed when Ansible cannot reach the machines")

    traffic = commands.add_parser("traffic", parents=[which], help="run real traffic between the machines and compare it with the policy")
    traffic.add_argument("--repeat", type=int, default=1, help="how many rounds (default: 1)")
    traffic.add_argument("--interval", type=int, default=10, help="seconds between rounds (default: 10)")

    commands.add_parser("check", parents=[common], help="test Segmentra's features against the running lab (changes it for a while, then restores it)")

    siem = commands.add_parser("siem", parents=[which], help="show what the sample SIEM received")
    siem.add_argument("--last", type=int, default=15, help="how many of the newest messages to show (default: 15)")
    siem.add_argument("--by-action", action="store_true", help="also count the messages per action")

    commands.add_parser("status", parents=[which], help="show what exists")

    down = commands.add_parser("down", parents=[common], help="remove the lab")
    down.add_argument("--remove-images", action="store_true", help="also remove the lab's images")

    args = parser.parse_args()
    if args.command == "up" and not args.api_url:
        args.api_url = default_api_url()
    try:
        return run_lab_command(args) or 0
    except LabError as error:
        print(f"\nError: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
