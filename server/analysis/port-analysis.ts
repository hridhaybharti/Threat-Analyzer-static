import { HeuristicResult } from "@shared/schema";

interface PortAnalysis {
  heuristics: HeuristicResult[];
  portRisk: "standard" | "suspicious" | "malicious";
  portNumber?: number;
}

export function analyzePort(url: URL): PortAnalysis {
  const heuristics: HeuristicResult[] = [];
  const port = url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80);
  
  // Standard ports mapping
  const standardPorts = {
    20: 'FTP Data',
    21: 'FTP Control', 
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    8080: 'HTTP Alternate',
    8443: 'HTTPS Alternate',
  };

  // Commonly abused ports
  const abusedPorts = [
    { port: 8080, reason: "Common proxy/C2 port" },
    { port: 8443, reason: "Common HTTPS alternate" },
    { port: 8888, reason: "Common development/proxy port" },
    { port: 9000, reason: "Common web service port" },
    { port: 9001, reason: "Common Tor/proxy port" },
    { port: 9002, reason: "Common web service port" },
    { port: 3128, reason: "Common proxy port" },
    { port: 1080, reason: "SOCKS proxy" },
    { port: 1337, reason: "Common backdoor port" },
    { port: 31337, reason: "Classic backdoor port" },
    { port: 12345, reason: "Common backdoor port" },
    { port: 54321, reason: "Common backdoor port" },
  ];

  // Database and service ports
  const servicePorts = [
    { port: 1433, service: "MSSQL", risk: "medium" },
    { port: 1521, service: "Oracle", risk: "medium" },
    { port: 2049, service: "NFS", risk: "high" },
    { port: 3306, service: "MySQL", risk: "medium" },
    { port: 3389, service: "RDP", risk: "high" },
    { port: 5432, service: "PostgreSQL", risk: "medium" },
    { port: 5984, service: "CouchDB", risk: "medium" },
    { port: 6379, service: "Redis", risk: "medium" },
    { port: 27017, service: "MongoDB", risk: "medium" },
  ];

  // P2P and torrent ports
  const p2pPorts = [
    { port: 6881, reason: "BitTorrent" },
    { port: 6882, reason: "BitTorrent" },
    { port: 6883, reason: "BitTorrent" },
    { port: 6884, reason: "BitTorrent" },
    { port: 6885, reason: "BitTorrent" },
    { port: 6886, reason: "BitTorrent" },
    { port: 6887, reason: "BitTorrent" },
    { port: 6888, reason: "BitTorrent" },
    { port: 6889, reason: "BitTorrent" },
  ];

  let portRisk: "standard" | "suspicious" | "malicious" = "standard";

  // 1. Check if it's a standard web port
  if (port === 80 || port === 443) {
    heuristics.push({
      name: "Standard Web Port",
      status: "pass" as const,
      description: `Using standard ${port === 80 ? 'HTTP' : 'HTTPS'} port`,
      scoreImpact: 0,
    });
  } 
  // Check for other standard ports
  else if (Object.keys(standardPorts).map(Number).includes(port)) {
    const portEntry = Object.entries(standardPorts).find(([p]) => parseInt(p) === port);
    const serviceName = portEntry ? portEntry[1] : "unknown service";
    heuristics.push({
      name: "Standard Port",
      status: "pass" as const,
      description: `Using standard port for ${serviceName}`,
      scoreImpact: 0,
    });
  } 
  // 2. Check for commonly abused ports
  else if (abusedPorts.some(p => p.port === port)) {
    const abused = abusedPorts.find(p => p.port === port);
    heuristics.push({
      name: "Abused Port",
      status: "fail" as const,
      description: `Port ${port} is commonly abused: ${abused?.reason}`,
      scoreImpact: 30,
    });
    portRisk = "malicious";
  }
  // 3. Check for database/service ports exposed to web
  else if (servicePorts.some(p => p.port === port)) {
    const service = servicePorts.find(p => p.port === port);
    const riskMultiplier = service?.risk === "high" ? 35 : service?.risk === "medium" ? 25 : 20;
    
    heuristics.push({
      name: "Service Port Exposure",
      status: "fail" as const,
      description: `Database/service port ${port} (${service?.service}) exposed to internet`,
      scoreImpact: riskMultiplier,
    });
    portRisk = "malicious";
  }
  // 4. Check for P2P/torrent ports
  else if (p2pPorts.some(p => p.port === port)) {
    heuristics.push({
      name: "P2P Port",
      status: "warn" as const,
      description: `Port ${port} commonly used for P2P file sharing`,
      scoreImpact: 20,
    });
    portRisk = "suspicious";
  }
  // 5. Check for high-numbered ports (often used for malware)
  else if (port > 10000) {
    heuristics.push({
      name: "High Port Number",
      status: "warn" as const,
      description: `High port number ${port} - often used for malware C2`,
      scoreImpact: 15,
    });
    portRisk = "suspicious";
  }
  // 6. Check for privileged ports (1-1023) that aren't standard
  else if (port < 1024 && !Object.keys(standardPorts).map(Number).includes(port)) {
    heuristics.push({
      name: "Non-Standard Privileged Port",
      status: "warn" as const,
      description: `Privileged port ${port} not associated with standard service`,
      scoreImpact: 20,
    });
    portRisk = "suspicious";
  }
  // 7. Check for known backdoor ports
  else if ([1337, 31337, 12345, 54321].includes(port)) {
    heuristics.push({
      name: "Backdoor Port",
      status: "fail" as const,
      description: `Port ${port} is a known backdoor/C2 port`,
      scoreImpact: 40,
    });
    portRisk = "malicious";
  }
  // 8. Check for non-standard web ports
  else if (port >= 8000 && port <= 8999) {
    heuristics.push({
      name: "Non-Standard Web Port",
      status: "warn" as const,
      description: `Non-standard web port ${port} - may be development server or proxy`,
      scoreImpact: 18,
    });
    portRisk = "suspicious";
  }
  // Other high ports (that aren't standard)
  else if (port > 1024 && port <= 65535 && !Object.keys(standardPorts).map(Number).includes(port)) {
    heuristics.push({
      name: "Non-Standard Port",
      status: "warn" as const,
      description: `Using non-standard port ${port}`,
      scoreImpact: 12,
    });
    portRisk = "suspicious";
  }

  // 9. Special case: Port mismatches (HTTP on 443, HTTPS on 80)
  if ((url.protocol === 'http:' && port === 443) || 
      (url.protocol === 'https:' && port === 80)) {
    heuristics.push({
      name: "Protocol Port Mismatch",
      status: "warn" as const,
      description: `Protocol/port mismatch detected - potential evasion attempt`,
      scoreImpact: 22,
    });
    if (portRisk === "standard") portRisk = "suspicious";
  }

  // 10. Multiple port patterns in hostname (potential evasion)
  const portPatternInHost = /:\d+/g;
  const matches = url.hostname.match(portPatternInHost);
  if (matches && matches.length > 1) {
    heuristics.push({
      name: "Multiple Port Patterns",
      status: "fail" as const,
      description: `Multiple port patterns detected in hostname: ${matches.length}`,
      scoreImpact: 35,
    });
    portRisk = "malicious";
  }

  return {
    heuristics,
    portRisk,
    portNumber: port
  };
}

// Detect if URL uses port-based evasion
export function detectPortEvasion(url: URL): HeuristicResult | null {
  const port = url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80);
  
  // Common evasion techniques
  const evasionPatterns = [
    { pattern: port === 8080 && url.protocol === 'https:', desc: "HTTPS on HTTP alternate port" },
    { pattern: port === 8443 && url.protocol === 'http:', desc: "HTTP on HTTPS alternate port" },
    { pattern: port > 50000, desc: "Very high port number for web service" },
    { pattern: [1337, 31337, 12345].includes(port), desc: "Known backdoor port" },
  ];

  for (const { pattern, desc } of evasionPatterns) {
    if (pattern) {
      return {
        name: "Port-Based Evasion",
        status: "fail" as const,
        description: desc,
        scoreImpact: 30,
      };
    }
  }

  return null;
}