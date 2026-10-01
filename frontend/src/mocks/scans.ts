import type { ScanRecord, Severity, Vulnerability } from "../types/scan";

function countBySeverity(vulnerabilities: Vulnerability[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const vuln of vulnerabilities) {
    counts[vuln.severity] += 1;
  }
  return counts;
}

const productionWebVulns: Vulnerability[] = [
  {
    id: "vuln-1",
    cve: "CVE-2024-3094",
    severity: "critical",
    host: "10.0.1.12",
    port: 22,
    service: "sshd (xz-utils backdoor)",
    cvss: 9.8,
    description:
      "A malicious backdoor was introduced into xz-utils 5.6.0/5.6.1 that allows remote code execution via a crafted SSH connection.",
    remediation: "Downgrade to xz-utils 5.4.x or apply the vendor patch immediately and rotate SSH host keys.",
  },
  {
    id: "vuln-2",
    cve: "CVE-2023-44487",
    severity: "high",
    host: "10.0.1.12",
    port: 443,
    service: "nginx/1.24.0",
    cvss: 7.5,
    description:
      "HTTP/2 Rapid Reset allows a remote attacker to cause denial of service via rapid stream creation and cancellation.",
    remediation: "Upgrade nginx to a patched release and enable stream rate limiting at the load balancer.",
  },
  {
    id: "vuln-3",
    cve: "CVE-2023-4863",
    severity: "high",
    host: "10.0.1.14",
    port: 443,
    service: "libwebp",
    cvss: 8.8,
    description: "Heap buffer overflow in libwebp image processing can lead to remote code execution.",
    remediation: "Update libwebp and any dependent image processing libraries to the patched version.",
  },
  {
    id: "vuln-4",
    cve: "CVE-2022-1388",
    severity: "medium",
    host: "10.0.1.20",
    port: 8443,
    service: "F5 BIG-IP iControl REST",
    cvss: 6.5,
    description: "Improper access control could allow authentication bypass for the iControl REST endpoint.",
    remediation: "Restrict management interface access to trusted networks and apply the vendor hotfix.",
  },
  {
    id: "vuln-5",
    cve: "CVE-2021-44228",
    severity: "critical",
    host: "10.0.1.31",
    port: 8080,
    service: "Apache Log4j 2.14.1",
    cvss: 10.0,
    description: "Log4Shell — unauthenticated remote code execution via JNDI lookups in log messages.",
    remediation: "Upgrade Log4j to 2.17.1+ or set log4j2.formatMsgNoLookups=true as an interim mitigation.",
  },
  {
    id: "vuln-6",
    cve: "CVE-2020-1938",
    severity: "medium",
    host: "10.0.1.31",
    port: 8009,
    service: "Apache Tomcat AJP",
    cvss: 5.9,
    description: "Ghostcat — the AJP connector allows reading of arbitrary files from the web application.",
    remediation: "Disable the AJP connector if unused, or bind it to localhost and require a shared secret.",
  },
  {
    id: "vuln-7",
    cve: "N/A",
    severity: "low",
    host: "10.0.1.45",
    port: 21,
    service: "FTP (anonymous login enabled)",
    cvss: 3.1,
    description: "Anonymous FTP login is enabled, exposing directory listings to unauthenticated users.",
    remediation: "Disable anonymous authentication or restrict the FTP service to internal maintenance windows.",
  },
  {
    id: "vuln-8",
    cve: "N/A",
    severity: "info",
    host: "10.0.1.45",
    port: 80,
    service: "HTTP (banner disclosure)",
    cvss: 0,
    description: "Server response headers disclose detailed version information useful for fingerprinting.",
    remediation: "Suppress or generalize the Server header at the reverse proxy layer.",
  },
];

const internalApiVulns: Vulnerability[] = [
  {
    id: "vuln-9",
    cve: "CVE-2023-38408",
    severity: "high",
    host: "10.0.2.5",
    port: 22,
    service: "OpenSSH 8.9",
    cvss: 9.8,
    description: "PKCS#11 feature in ssh-agent could allow remote code execution via a forwarded agent socket.",
    remediation: "Upgrade OpenSSH to 9.3p2 or later and disable agent forwarding where not required.",
  },
  {
    id: "vuln-10",
    cve: "CVE-2022-3602",
    severity: "medium",
    host: "10.0.2.9",
    port: 443,
    service: "OpenSSL 3.0.6",
    cvss: 7.5,
    description: "X.509 punycode buffer overflow when verifying certificate name constraints.",
    remediation: "Upgrade OpenSSL to 3.0.7 or later on all affected hosts.",
  },
];

export const mockScans: ScanRecord[] = [
  {
    id: "scan-1024",
    target: "10.0.1.0/24 (production-web)",
    startedAt: "2026-09-15T14:32:00Z",
    status: "completed",
    totalFindings: productionWebVulns.length,
    severityCounts: countBySeverity(productionWebVulns),
    config: {
      target: "10.0.1.0/24",
      portRange: "1-1024",
      scanType: "full",
      scanDepth: "deep",
    },
    vulnerabilities: productionWebVulns,
  },
  {
    id: "scan-1019",
    target: "10.0.2.0/24 (internal-api)",
    startedAt: "2026-09-12T09:10:00Z",
    status: "completed",
    totalFindings: internalApiVulns.length,
    severityCounts: countBySeverity(internalApiVulns),
    config: {
      target: "10.0.2.0/24",
      portRange: "1-65535",
      scanType: "full",
      scanDepth: "standard",
    },
    vulnerabilities: internalApiVulns,
  },
  {
    id: "scan-1007",
    target: "staging.internal.example.com",
    startedAt: "2026-09-08T22:00:00Z",
    status: "failed",
    totalFindings: 0,
    severityCounts: countBySeverity([]),
    config: {
      target: "staging.internal.example.com",
      portRange: "1-1024",
      scanType: "quick",
      scanDepth: "light",
    },
    vulnerabilities: [],
  },
];

export const latestScan = mockScans[0];
