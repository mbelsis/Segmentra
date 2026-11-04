# Screenshots

Click an image to open it full size. The screenshots show the sample dataset that ships with the repository: load it with `npm run db:demo` after the migrations and the seed (see [Demo data](demo-data.md)) to get the same hosts, policies, OT devices and deployments on your own installation. You can also use the ready-made [test labs](lab.md), which uses Docker to set up a live network with three hosts and a syslog collector, so you can see the application working on real firewalls. Screenshots 13 to 19 were taken with the lab.

<table>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/01-dashboard.png"><img src="screenshots/01-dashboard.png" alt="Dashboard" width="100%"></a><br>
      <b>Dashboard</b><br>
      <sub>Deployment statistics, managed hosts, IoT assets, pending approvals and the latest security audit</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/02-policy-sets.png"><img src="screenshots/02-policy-sets.png" alt="Policy Sets" width="100%"></a><br>
      <b>Policy Sets</b><br>
      <sub>Policies with their scope (tag, VLAN or host list) and the status of every version</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/03-policy-rules.png"><img src="screenshots/03-policy-rules.png" alt="Policy Rules" width="100%"></a><br>
      <b>Policy Rules</b><br>
      <sub>Interface scope, the automatic baseline rules and the rules of a policy version</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/04-approvals.png"><img src="screenshots/04-approvals.png" alt="Approvals" width="100%"></a><br>
      <b>Approvals</b><br>
      <sub>Versions waiting for review, with the requester and the reason</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/05-inventory.png"><img src="screenshots/05-inventory.png" alt="Inventory" width="100%"></a><br>
      <b>Inventory</b><br>
      <sub>Hosts with tags, VLAN, backend, SSH credential, compliance, and the <b>Active Rules</b> action</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/06-ot-iot.png"><img src="screenshots/06-ot-iot.png" alt="OT/IoT" width="100%"></a><br>
      <b>OT/IoT</b><br>
      <sub>Devices behind a gateway with vendor, zone, criticality and coverage</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/07-docker-swarm.png"><img src="screenshots/07-docker-swarm.png" alt="Docker Swarm" width="100%"></a><br>
      <b>Docker Swarm</b><br>
      <sub>Setup guide and overview of the registered Swarm nodes</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/08-troubleshoot.png"><img src="screenshots/08-troubleshoot.png" alt="Troubleshoot" width="100%"></a><br>
      <b>Troubleshoot</b><br>
      <sub>Firewall Learning, the communication simulator and policy search by IP or host</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/09-policy-impact-analysis.png"><img src="screenshots/09-policy-impact-analysis.png" alt="Policy Impact Analysis" width="100%"></a><br>
      <b>Policy Impact Analysis</b><br>
      <sub>Test a policy against real traffic in log-only mode before enforcing it</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/10-security-audit.png"><img src="screenshots/10-security-audit.png" alt="Security Audit" width="100%"></a><br>
      <b>Security Audit</b><br>
      <sub>Findings by severity: broad rules, duplicates, hosts without a deployed policy</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/11-audit-log.png"><img src="screenshots/11-audit-log.png" alt="Audit Log" width="100%"></a><br>
      <b>Audit Log</b><br>
      <sub>Every change, approval and deployment, with actor and details</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/12-admin.png"><img src="screenshots/12-admin.png" alt="Admin" width="100%"></a><br>
      <b>Admin</b><br>
      <sub>LDAP group mappings, SSH and Kubernetes credentials, users and roles</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/13-inventory-actions.png"><img src="screenshots/13-inventory-actions.png" alt="Inventory with the test lab" width="100%"></a><br>
      <b>Inventory with the test lab</b><br>
      <sub>The machines from the <a href="lab.md">test lab</a>, each with one <b>Actions</b> menu</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/14-firewall-logs.png"><img src="screenshots/14-firewall-logs.png" alt="Peek at Logs" width="100%"></a><br>
      <b>Peek at Logs</b><br>
      <sub>A host's recent firewall log, accepted and denied, with the rule that decided</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/15-policy-visualization.png"><img src="screenshots/15-policy-visualization.png" alt="Policy Visualization" width="100%"></a><br>
      <b>Policy Visualization</b><br>
      <sub>Who may reach a host, and on which ports, as a diagram</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/16-host-readiness.png"><img src="screenshots/16-host-readiness.png" alt="Check Readiness" width="100%"></a><br>
      <b>Check Readiness</b><br>
      <sub>Whether a host can take a policy, and whether its rules would survive a reboot</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/17-policy-test-running.png"><img src="screenshots/17-policy-test-running.png" alt="A policy test running" width="100%"></a><br>
      <b>A policy test running</b><br>
      <sub>Traffic being captured in log-only mode, with the time left until the original rules return</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/18-compliance-report.png"><img src="screenshots/18-compliance-report.png" alt="Compliance Report" width="100%"></a><br>
      <b>Compliance Report</b><br>
      <sub>Evidence from Segmentra's own data, mapped to PCI DSS, ISO 27001, SOC 2 and HIPAA controls</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/19-audit-log-deployment.png"><img src="screenshots/19-audit-log-deployment.png" alt="Audit Log of a deployment" width="100%"></a><br>
      <b>Audit Log of a deployment</b><br>
      <sub>Who approved and started it, which hosts it reached and how it ended</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/20-auto-tagging.png"><img src="screenshots/20-auto-tagging.png" alt="Auto-Tagging" width="100%"></a><br>
      <b>Auto-Tagging</b><br>
      <sub>Rules that tag hosts by hostname, IP, OS or VLAN, with examples</sub>
    </td>
    <td align="center" width="33%">
      <a href="screenshots/21-inventory-discovery.png"><img src="screenshots/21-inventory-discovery.png" alt="Inventory Discovery" width="100%"></a><br>
      <b>Inventory Discovery</b><br>
      <sub>Scan networks for SSH servers and import new hosts with a default tag</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screenshots/22-deployment-modes.png"><img src="screenshots/22-deployment-modes.png" alt="Deployment modes" width="100%"></a><br>
      <b>Deployment modes</b><br>
      <sub>Canary, Progressive and Full, explained where you filter and choose them</sub>
    </td>
  </tr>
</table>
