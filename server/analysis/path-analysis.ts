import { HeuristicResult } from "@shared/schema";

interface PathAnalysis {
  heuristics: HeuristicResult[];
  suspiciousScore: number;
  pathType: "normal" | "suspicious" | "malicious";
}

export function analyzeURLPath(path: string, query: string = ""): PathAnalysis {
  const heuristics: HeuristicResult[] = [];
  let suspiciousScore = 0;
  
  const fullPath = path + (query ? `?${query}` : "");

  // 1. Directory Traversal Detection
  const traversalPatterns = [
    /\.\.[\/\\]/,          // ../
    /%2e%2e[\/\\]/,       // encoded ../
    /\.\.%2f/,             // .%2f
    /%2e%2e%2f/,          // %2e%2e%2f (../)
    /..%5c/,               // ..\ (encoded)
    /\.\.[\/\\]\.\.[\/\\]/, // ../../
  ];

  let hasTraversal = false;
  for (const pattern of traversalPatterns) {
    if (pattern.test(fullPath.toLowerCase())) {
      hasTraversal = true;
      break;
    }
  }

  if (hasTraversal) {
    heuristics.push({
      name: "Directory Traversal",
      status: "fail" as const,
      description: "Path traversal attempt detected (../ or encoded variants)",
      scoreImpact: 45,
    });
    suspiciousScore += 9;
  }

  // 2. Command Injection Patterns
  const commandPatterns = [
    /[;&|`$()]/,           // Command separators
    /wget|curl|nc|netcat/, // Download tools
    /powershell|cmd\.exe/, // Windows commands
    /bash|sh\s+/i,         // Shell commands
    /eval\s*\(|exec\s*\(/, // Code execution
    /system\s*\(/,         // System calls
  ];

  let hasCommands = false;
  for (const pattern of commandPatterns) {
    if (pattern.test(fullPath.toLowerCase())) {
      hasCommands = true;
      break;
    }
  }

  if (hasCommands) {
    heuristics.push({
      name: "Command Injection",
      status: "fail" as const,
      description: "Command execution patterns detected in path",
      scoreImpact: 50,
    });
    suspiciousScore += 10;
  }

  // 3. Suspicious File Extensions
  const maliciousExtensions = [
    '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js', '.jar',
    '.ps1', '.sh', '.php', '.asp', '.aspx', '.jsp', '.rb', '.py', '.pl'
  ];

  const suspiciousExtensions = [
    '.zip', '.rar', '.7z', '.tar', '.gz', '.doc', '.docx', '.pdf', '.xls',
    '.xlsx', '.ppt', '.pptx', '.iso', '.dmg', '.pkg', '.deb', '.rpm', '.msi'
  ];

  const pathLower = path.toLowerCase();
  
  for (const ext of maliciousExtensions) {
    if (pathLower.includes(ext)) {
      heuristics.push({
        name: "Malicious File Extension",
        status: "fail" as const,
        description: `File execution extension detected: ${ext}`,
        scoreImpact: 40,
      });
      suspiciousScore += 8;
      break;
    }
  }

  for (const ext of suspiciousExtensions) {
    if (pathLower.includes(ext)) {
      heuristics.push({
        name: "Suspicious File Extension",
        status: "warn" as const,
        description: `Potentially malicious file type: ${ext}`,
        scoreImpact: 20,
      });
      suspiciousScore += 4;
      break;
    }
  }

  // 4. Double Extensions
  const doubleExtPattern = /\.[a-zA-Z0-9]{2,4}\.[a-zA-Z0-9]{2,4}$/i;
  if (doubleExtPattern.test(path)) {
    heuristics.push({
      name: "Double Extension",
      status: "warn" as const,
      description: "Double file extension detected - evasion technique",
      scoreImpact: 25,
    });
    suspiciousScore += 5;
  }

  // 5. Suspicious Path Components
  const suspiciousPaths = [
    'admin', 'administrator', 'wp-admin', 'phpmyadmin', 'mysql',
    'config', 'configuration', 'backup', 'database', 'db',
    'panel', 'cpanel', 'control', 'manage',
    'upload', 'uploads', 'files', 'download', 'downloads',
    'temp', 'tmp', 'cache', 'logs',
    '.git', '.svn', '.env', 'config.php', 'web.config'
  ];

  for (const suspiciousPath of suspiciousPaths) {
    if (pathLower.includes(suspiciousPath)) {
      heuristics.push({
        name: "Sensitive Path",
        status: "warn" as const,
        description: `Access to sensitive directory: ${suspiciousPath}`,
        scoreImpact: 15,
      });
      suspiciousScore += 3;
      break;
    }
  }

  // 6. URL Parameter Manipulation
  const suspiciousParams = [
    'id=', 'file=', 'page=', 'dir=', 'path=', 'folder=',
    'document=', 'download=', 'redirect=', 'url=', 'return=',
    'cmd=', 'exec=', 'eval=', 'system=', 'shell='
  ];

  const queryLower = query.toLowerCase();
  let paramCount = 0;
  
  for (const param of suspiciousParams) {
    if (queryLower.includes(param)) {
      paramCount++;
    }
  }

  if (paramCount >= 3) {
    heuristics.push({
      name: "Parameter Manipulation",
      status: "fail" as const,
      description: `Multiple suspicious parameters detected: ${paramCount}`,
      scoreImpact: 30,
    });
    suspiciousScore += 6;
  } else if (paramCount >= 1) {
    heuristics.push({
      name: "Suspicious Parameters",
      status: "warn" as const,
      description: `Suspicious URL parameters detected: ${paramCount}`,
      scoreImpact: 15,
    });
    suspiciousScore += 3;
  }

  // 7. Encoding in Path
  const encodingPatterns = [
    /%[0-9A-Fa-f]{2}/,           // URL encoding
    /&#x?[0-9A-Fa-f]+;/,          // HTML entities
    /\\u[0-9A-Fa-f]{4}/,          // Unicode escape
    /\\x[0-9A-Fa-f]{2}/g,           // Hex escape
  ];

  let encodingCount = 0;
  for (const pattern of encodingPatterns) {
    if (pattern.test(fullPath)) {
      encodingCount++;
    }
  }

  if (encodingCount >= 3) {
    heuristics.push({
      name: "Heavy Path Encoding",
      status: "fail" as const,
      description: `Multiple encoding types in path: ${encodingCount}`,
      scoreImpact: 35,
    });
    suspiciousScore += 7;
  } else if (encodingCount >= 1) {
    heuristics.push({
      name: "Path Encoding",
      status: "warn" as const,
      description: "Encoded characters detected in path",
      scoreImpact: 20,
    });
    suspiciousScore += 4;
  }

  // 8. Very Long Paths (potential buffer overflow)
  if (fullPath.length > 1000) {
    heuristics.push({
      name: "Long Path",
      status: "fail" as const,
      description: `Extremely long path detected: ${fullPath.length} characters`,
      scoreImpact: 30,
    });
    suspiciousScore += 6;
  } else if (fullPath.length > 500) {
    heuristics.push({
      name: "Long Path",
      status: "warn" as const,
      description: `Long path detected: ${fullPath.length} characters`,
      scoreImpact: 15,
    });
    suspiciousScore += 3;
  }

  // 9. Non-ASCII Characters in Path
  const nonAsciiPattern = /[^\x00-\x7F]/;
  if (nonAsciiPattern.test(fullPath)) {
    heuristics.push({
      name: "Non-ASCII Path",
      status: "warn" as const,
      description: "Non-ASCII characters detected in URL path",
      scoreImpact: 20,
    });
    suspiciousScore += 4;
  }

  // 10. Path-based Bypass Attempts
  const bypassPatterns = [
    /%00/,                   // Null byte injection
    /\/\.\//,                // /./
    /\/\.\.\/\.\.\//,        // Directory traversal with current dir
    /\/\//,                  // Double slash
    /\/\s+\//,               // Space in path
    /\/\+/g,                 // Plus in path
  ];

  let hasBypass = false;
  for (const pattern of bypassPatterns) {
    if (pattern.test(fullPath)) {
      hasBypass = true;
      break;
    }
  }

  if (hasBypass) {
    heuristics.push({
      name: "Path Bypass Attempt",
      status: "fail" as const,
      description: "Path manipulation bypass techniques detected",
      scoreImpact: 35,
    });
    suspiciousScore += 7;
  }

  // Determine path type
  let pathType: "normal" | "suspicious" | "malicious" = "normal";
  if (suspiciousScore >= 15) pathType = "malicious";
  else if (suspiciousScore >= 6) pathType = "suspicious";

  return {
    heuristics,
    suspiciousScore,
    pathType
  };
}