/**
 * Parse firewall audit logs to extract communication flows
 */
/**
 * Parse firewall log file and extract communication flows
 */
export function parseFirewallLogs(logContent) {
    const lines = logContent.split('\n').filter(line => line.trim().length > 0);
    const entries = [];
    for (const line of lines) {
        try {
            const entry = parseLogLine(line);
            if (entry) {
                entries.push(entry);
            }
        }
        catch (error) {
            // Skip unparseable lines
            continue;
        }
    }
    return entries;
}
/**
 * Parse a single log line
 * Supports both nftables and iptables log formats
 */
function parseLogLine(line) {
    // Look for FW-AUDIT prefix
    if (!line.includes('FW-AUDIT')) {
        return null;
    }
    // Extract timestamp (format varies by system)
    const timestampMatch = line.match(/^(\w+\s+\d+\s+\d+:\d+:\d+)|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
    const timestamp = timestampMatch ? timestampMatch[0] : new Date().toISOString();
    // Extract direction from chain name or log prefix
    let direction = 'IN';
    if (line.includes('OUTPUT') || line.includes('output') || line.includes('OUT:')) {
        direction = 'OUT';
    }
    else if (line.includes('INPUT') || line.includes('input') || line.includes('IN:')) {
        direction = 'IN';
    }
    // Extract IP addresses
    // Common formats:
    // - SRC=1.2.3.4 DST=5.6.7.8
    // - src=1.2.3.4 dst=5.6.7.8
    // - SRC IP: 1.2.3.4 DST IP: 5.6.7.8
    // - ip saddr 1.2.3.4 ip daddr 5.6.7.8
    let sourceIp = '';
    let destinationIp = '';
    const srcMatch = line.match(/(?:SRC|src|SRC IP|source)[=:\s]+(\d+\.\d+\.\d+\.\d+)/i);
    if (srcMatch) {
        sourceIp = srcMatch[1];
    }
    else {
        const saddrMatch = line.match(/ip\s+saddr\s+(\d+\.\d+\.\d+\.\d+)/i);
        if (saddrMatch) {
            sourceIp = saddrMatch[1];
        }
    }
    const dstMatch = line.match(/(?:DST|dst|DST IP|destination)[=:\s]+(\d+\.\d+\.\d+\.\d+)/i);
    if (dstMatch) {
        destinationIp = dstMatch[1];
    }
    else {
        const daddrMatch = line.match(/ip\s+daddr\s+(\d+\.\d+\.\d+\.\d+)/i);
        if (daddrMatch) {
            destinationIp = daddrMatch[1];
        }
    }
    // Extract protocol
    let protocol = 'unknown';
    if (line.match(/\bTCP\b|\btcp\b/)) {
        protocol = 'tcp';
    }
    else if (line.match(/\bUDP\b|\budp\b/)) {
        protocol = 'udp';
    }
    else if (line.match(/\bICMP\b|\bicmp\b/)) {
        protocol = 'icmp';
    }
    // Extract ports
    let sourcePort;
    let destinationPort;
    // Format: SPT=12345 DPT=80 or sport=12345 dport=80
    const sptMatch = line.match(/(?:SPT|sport)[=:\s]+(\d+)/i);
    if (sptMatch) {
        sourcePort = parseInt(sptMatch[1], 10);
    }
    const dptMatch = line.match(/(?:DPT|dport)[=:\s]+(\d+)/i);
    if (dptMatch) {
        destinationPort = parseInt(dptMatch[1], 10);
    }
    // Extract action from log prefix
    let action = 'ALLOW';
    if (line.includes('FW-AUDIT: DENY') || line.includes('FW-AUDIT: DROP')) {
        action = 'DENY';
    }
    else if (line.includes('FW-AUDIT: ALLOW') || line.includes('FW-AUDIT: ACCEPT')) {
        action = 'ALLOW';
    }
    // If we couldn't extract IPs, skip this entry
    if (!sourceIp && !destinationIp) {
        return null;
    }
    // For OUT direction, swap IPs if needed (source is local, destination is remote)
    // For IN direction, source is remote, destination is local
    if (direction === 'OUT' && sourceIp && !destinationIp) {
        // Sometimes OUT logs only show destination
        const daddrMatch = line.match(/ip\s+daddr\s+(\d+\.\d+\.\d+\.\d+)/i);
        if (daddrMatch) {
            destinationIp = daddrMatch[1];
        }
    }
    return {
        timestamp,
        direction,
        sourceIp: sourceIp || 'unknown',
        destinationIp: destinationIp || 'unknown',
        protocol,
        sourcePort,
        destinationPort,
        action,
        rawLine: line
    };
}
/**
 * Group parsed log entries into communication flows
 */
export function groupCommunicationFlows(entries) {
    const flowMap = new Map();
    for (const entry of entries) {
        // Create a key for this flow
        const key = `${entry.direction}:${entry.sourceIp}:${entry.destinationIp}:${entry.protocol}:${entry.sourcePort || '*'}:${entry.destinationPort || '*'}`;
        if (!flowMap.has(key)) {
            flowMap.set(key, {
                direction: entry.direction,
                sourceIp: entry.sourceIp,
                destinationIp: entry.destinationIp,
                protocol: entry.protocol,
                sourcePort: entry.sourcePort,
                destinationPort: entry.destinationPort,
                count: 0,
                firstSeen: entry.timestamp,
                lastSeen: entry.timestamp
            });
        }
        const flow = flowMap.get(key);
        flow.count++;
        if (entry.timestamp < flow.firstSeen) {
            flow.firstSeen = entry.timestamp;
        }
        if (entry.timestamp > flow.lastSeen) {
            flow.lastSeen = entry.timestamp;
        }
    }
    return Array.from(flowMap.values()).sort((a, b) => b.count - a.count);
}
