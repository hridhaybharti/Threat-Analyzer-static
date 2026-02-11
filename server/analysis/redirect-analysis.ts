import { HeuristicResult } from "@shared/schema";

interface RedirectAnalysis {
  heuristics: HeuristicResult[];
  redirectChains: number;
  shortenerDetected: boolean;
  suspiciousRedirects: boolean;
}

export function analyzeRedirects(url: URL): RedirectAnalysis {
  const heuristics: HeuristicResult[] = [];
  let redirectChains = 0;
  let shortenerDetected = false;
  let suspiciousRedirects = false;

  // 1. Known URL Shortener Detection
  const shortenerDomains = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'short.io', 'cutt.ly', 'tiny.cc', 'rb.gy', 'clk.im',
    'yourls.org', 'snip.ly', 'linktr.ee', 'short.link', 'soo.gd',
    'adf.ly', 'bit.do', 'mcaf.ee', 'viralurl.com', 'virurl.com',
    'ity.im', 'q.gs', 'po.st', 'bc.vc', 'twitthis.com', 'u.to',
    'j.mp', 'buzurl.com', 'tweetme.me', 'dft.ba', 'lnkd.in',
    'db.tt', 'qr.ae', 'adfly.com', 'goo.gl', 'bitly.com',
    'cur.lv', 'tinyurl.com', 'ow.ly', 'ity.im', 'to.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'qr.net', '1url.com',
    'tweez.me', 'vzturl.com', 'zip.net', 'rubyurl.com',
    'omf.gd', 'to.im', 'link.zip.net'
  ];

  const hostname = url.hostname.toLowerCase();
  
  if (shortenerDomains.some(shortener => hostname.includes(shortener) || hostname.endsWith(shortener))) {
    heuristics.push({
      name: "URL Shortener Detected",
      status: "warn" as const,
      description: `URL shortener service detected: ${hostname}`,
      scoreImpact: 20,
    });
    shortenerDetected = true;
    redirectChains++; // Assume at least one redirect
  }

  // 2. Redirect Parameter Detection
  const redirectPatterns = [
    /[?&]url=/i,           // ?url= or &url=
    /[?&]redirect=/i,       // ?redirect= or &redirect=
    /[?&]return=/i,        // ?return= or &return=
    /[?&]goto=/i,          // ?goto= or &goto=
    /[?&]link=/i,          // ?link= or &link=
    /[?&]dest=/i,          // ?dest= or &dest=
    /[?&]destination=/i,    // ?destination= or &destination=
    /[?&]next=/i,          // ?next= or &next=
    /[?&]target=/i,        // ?target= or &target=
    /[?&]r=/i,             // ?r= or &r= (common for redirect)
    /[?&]redir=/i,         // ?redir= or &redir=
    /\/redirect\//i,        // /redirect/ in path
    /\/r\/\?/,             // /r/ followed by query
  ];

  let redirectParamCount = 0;
  const urlStr = url.toString();
  
  for (const pattern of redirectPatterns) {
    if (pattern.test(urlStr)) {
      redirectParamCount++;
    }
  }

  if (redirectParamCount >= 2) {
    heuristics.push({
      name: "Multiple Redirect Parameters",
      status: "fail" as const,
      description: `Multiple redirect parameters detected: ${redirectParamCount}`,
      scoreImpact: 35,
    });
    suspiciousRedirects = true;
    redirectChains += 2;
  } else if (redirectParamCount >= 1) {
    heuristics.push({
      name: "Redirect Parameter",
      status: "warn" as const,
      description: "URL redirect parameter detected",
      scoreImpact: 18,
    });
    redirectChains++;
  }

  // 3. JavaScript Redirect Detection
  const jsRedirectPatterns = [
    /javascript:/i,
    /data:text\/html/i,
    /vbscript:/i,
  ];

  for (const pattern of jsRedirectPatterns) {
    if (pattern.test(urlStr)) {
      heuristics.push({
        name: "JavaScript Redirect",
        status: "fail" as const,
        description: "JavaScript-based redirect protocol detected",
        scoreImpact: 45,
      });
      suspiciousRedirects = true;
      redirectChains += 3;
      break;
    }
  }

  // 4. Meta Refresh Detection (in URL parameter)
  if (urlStr.includes('meta+refresh') || urlStr.includes('meta_refresh')) {
    heuristics.push({
      name: "Meta Refresh Redirect",
      status: "warn" as const,
      description: "Meta refresh redirect pattern detected",
      scoreImpact: 25,
    });
    redirectChains++;
  }

  // 5. Frame Redirect Detection
  const framePatterns = [
    /<iframe/i,
    /<frame/i,
    /frameset/i,
  ];

  for (const pattern of framePatterns) {
    if (pattern.test(urlStr)) {
      heuristics.push({
        name: "Frame Redirect",
        status: "fail" as const,
        description: "Frame-based redirect detected",
        scoreImpact: 30,
      });
      suspiciousRedirects = true;
      redirectChains += 2;
      break;
    }
  }

  // 6. HTTP Status Code Patterns
  const statusCodePatterns = [
    /\b30[0127]\b/,  // 300, 301, 302, 307
    /\b40[13]\b/,    // 401, 403 (can be used in redirect flows)
  ];

  for (const pattern of statusCodePatterns) {
    if (pattern.test(urlStr)) {
      heuristics.push({
        name: "HTTP Redirect Status",
        status: "warn" as const,
        description: "HTTP redirect status code detected in URL",
        scoreImpact: 15,
      });
      redirectChains++;
      break;
    }
  }

  // 7. Open Redirect Detection
  const openRedirectPatterns = [
    /\/\//.test(url.pathname),           // Double slash after protocol
    /[?&]url=https?:\/\//i,             // URL parameter with full URL
    /[?&]redirect=https?:\/\//i,        // Redirect parameter with full URL
    /[?&]goto=https?:\/\//i,            // Goto parameter with full URL
    /[?&]return=https?:\/\//i,          // Return parameter with full URL
  ];

  let openRedirectCount = 0;
  for (const pattern of openRedirectPatterns) {
    if (pattern) {
      openRedirectCount++;
    }
  }

  if (openRedirectCount >= 2) {
    heuristics.push({
      name: "Open Redirect",
      status: "fail" as const,
      description: `Open redirect vulnerability pattern detected: ${openRedirectCount} indicators`,
      scoreImpact: 40,
    });
    suspiciousRedirects = true;
    redirectChains += 2;
  }

  // 8. URL Chain Length Estimation
  const chainPatterns = [
    /\?ref=.*&ref=/i,                   // Multiple ref parameters
    /\?url=.*&url=/i,                   // Multiple URL parameters
    /\?redirect=.*&redirect=/i,         // Multiple redirect parameters
    /->/,                                // Arrow notation
    /[?&]step=/i,                       // Step parameters
  ];

  let chainIndicators = 0;
  for (const pattern of chainPatterns) {
    if (pattern.test(urlStr)) {
      chainIndicators++;
    }
  }

  if (chainIndicators >= 2) {
    heuristics.push({
      name: "Potential Redirect Chain",
      status: "fail" as const,
      description: `Multiple redirect chain indicators: ${chainIndicators}`,
      scoreImpact: 30,
    });
    redirectChains += chainIndicators;
  } else if (chainIndicators >= 1) {
    heuristics.push({
      name: "Redirect Chain Indicator",
      status: "warn" as const,
      description: "Possible redirect chain detected",
      scoreImpact: 15,
    });
    redirectChains++;
  }

  // 9. Suspicious Redirect Domains
  const suspiciousRedirectDomains = [
    'redirect', 'go', 'link', 'click', 'visit', 'jump', 'away',
    'out', 'exit', 'leave', 'next', 'continue', 'proceed'
  ];

  const pathLower = url.pathname.toLowerCase();
  const hasSuspiciousRedirectDomain = suspiciousRedirectDomains.some(domain => 
    hostname.includes(domain) || pathLower.includes(`/${domain}/`)
  );

  if (hasSuspiciousRedirectDomain) {
    heuristics.push({
      name: "Suspicious Redirect Domain",
      status: "warn" as const,
      description: "Domain or path contains redirect-related keywords",
      scoreImpact: 20,
    });
    redirectChains++;
  }

  // 10. QR Code Redirect Patterns
  const qrPatterns = [
    /qr/i,
    /scan/i,
    /barcode/i,
    /code/i,
  ];

  let qrIndicatorCount = 0;
  for (const pattern of qrPatterns) {
    if (pattern.test(urlStr)) {
      qrIndicatorCount++;
    }
  }

  if (qrIndicatorCount >= 2) {
    heuristics.push({
      name: "QR Code Redirect",
      status: "warn" as const,
      description: "QR code-related redirect patterns detected",
      scoreImpact: 22,
    });
    redirectChains++;
  }

  // 11. Base64-encoded URLs in parameters
  const base64Pattern = /[?&](url|redirect|goto|return)=([A-Za-z0-9+/]{20,}={0,2})/i;
  const base64Match = urlStr.match(base64Pattern);
  
  if (base64Match) {
    try {
      // Try to decode to see if it's a URL
      const decoded = Buffer.from(base64Match[2], 'base64').toString('utf8');
      if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
        heuristics.push({
          name: "Base64 URL Redirect",
          status: "fail" as const,
          description: "Base64-encoded URL detected in redirect parameter",
          scoreImpact: 35,
        });
        suspiciousRedirects = true;
        redirectChains += 2;
      }
    } catch {
      // Invalid base64
    }
  }

  return {
    heuristics,
    redirectChains,
    shortenerDetected,
    suspiciousRedirects
  };
}

// Detect if URL is likely part of a phishing redirect chain
export function detectPhishingRedirectChain(url: URL): HeuristicResult | null {
  const analysis = analyzeRedirects(url);
  
  if (analysis.suspiciousRedirects && analysis.redirectChains >= 3) {
    return {
      name: "Phishing Redirect Chain",
      status: "fail" as const,
      description: `Suspicious redirect chain with ${analysis.redirectChains} hops - common in phishing attacks`,
      scoreImpact: 40,
    };
  }
  
  if (analysis.shortenerDetected && analysis.suspiciousRedirects) {
    return {
      name: "Shortener + Redirect",
      status: "fail" as const,
      description: "URL shortener combined with redirect patterns - high phishing risk",
      scoreImpact: 35,
    };
  }
  
  return null;
}