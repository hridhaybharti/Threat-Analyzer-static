import { HeuristicResult } from "@shared/schema";

interface ObfuscationAnalysis {
  heuristics: HeuristicResult[];
  decodedContent: string;
  obfuscationLevel: "none" | "low" | "medium" | "high";
}

export function analyzeObfuscation(input: string): ObfuscationAnalysis {
  const heuristics: HeuristicResult[] = [];
  let decodedContent = input;
  let obfuscationScore = 0;

  // 1. Base64 Detection
  const base64Pattern = /^[A-Za-z0-9+/]{4,}={0,2}$/;
  const suspectBase64 = /^[A-Za-z0-9+/]{20,}={0,2}$/;
  
  if (base64Pattern.test(input)) {
    heuristics.push({
      name: "Base64 Encoding",
      status: "warn" as const,
      description: "Base64 encoded content detected",
      scoreImpact: 20,
    });
    obfuscationScore += 2;
    
    // Try to decode
    try {
      const decoded = Buffer.from(input, 'base64').toString('utf8');
      if (decoded && /^[a-zA-Z0-9.-]+$/.test(decoded)) {
        decodedContent = decoded;
        heuristics.push({
          name: "Base64 Decoding",
          status: "pass" as const,
          description: "Successfully decoded Base64 content",
          scoreImpact: 0,
        });
        obfuscationScore += 3;
      }
    } catch {
      heuristics.push({
        name: "Invalid Base64",
        status: "fail" as const,
        description: "Malformed Base64 encoding",
        scoreImpact: 15,
      });
    }
  } else if (suspectBase64.test(input)) {
    heuristics.push({
      name: "Potential Base64",
      status: "warn" as const,
      description: "Content may be Base64 encoded",
      scoreImpact: 10,
    });
    obfuscationScore += 1;
  }

  // 2. Hex Encoding Detection
  const hexPattern = /^[0-9A-Fa-f\s]+$/;
  const suspectHex = /(?:[0-9A-Fa-f]{2}){5,}/;
  
  if (hexPattern.test(input.replace(/\s/g, ''))) {
    heuristics.push({
      name: "Hex Encoding",
      status: "warn" as const,
      description: "Hexadecimal encoding detected",
      scoreImpact: 25,
    });
    obfuscationScore += 3;
    
    // Try to decode
    try {
      const cleanHex = input.replace(/\s/g, '');
      if (cleanHex.length % 2 === 0) {
        const decoded = Buffer.from(cleanHex, 'hex').toString('utf8');
        if (decoded) {
          decodedContent = decoded;
          heuristics.push({
            name: "Hex Decoding",
            status: "pass" as const,
            description: "Successfully decoded hexadecimal content",
            scoreImpact: 0,
          });
          obfuscationScore += 2;
        }
      }
    } catch {
      heuristics.push({
        name: "Invalid Hex",
        status: "fail" as const,
        description: "Malformed hexadecimal encoding",
        scoreImpact: 20,
      });
    }
  } else if (suspectHex.test(input)) {
    heuristics.push({
      name: "Potential Hex",
      status: "warn" as const,
      description: "Content may contain hexadecimal encoding",
      scoreImpact: 15,
    });
    obfuscationScore += 2;
  }

  // 3. Character Substitution Patterns
  const substitutionPatterns = [
    { pattern: /@/, desc: "Symbol substitution (@ for a)" },
    { pattern: /\$/, desc: "Symbol substitution ($ for s)" },
    { pattern: /0/, desc: "Number substitution (0 for o)" },
    { pattern: /1/, desc: "Number substitution (1 for i/l)" },
    { pattern: /3/, desc: "Number substitution (3 for e)" },
    { pattern: /5/, desc: "Number substitution (5 for s)" },
    { pattern: /7/, desc: "Number substitution (7 for t)" },
    { pattern: /\[\]/, desc: "Bracket substitution" },
    { pattern: /\(\)/, desc: "Parenthesis substitution" },
    { pattern: /\{\}/, desc: "Brace substitution" },
  ];

  let substitutionCount = 0;
  for (const { pattern, desc } of substitutionPatterns) {
    if (pattern.test(input)) {
      substitutionCount++;
    }
  }

  if (substitutionCount >= 3) {
    heuristics.push({
      name: "Heavy Character Substitution",
      status: "fail" as const,
      description: `Multiple character substitutions detected: ${substitutionCount} patterns`,
      scoreImpact: 30,
    });
    obfuscationScore += 4;
  } else if (substitutionCount >= 1) {
    heuristics.push({
      name: "Character Substitution",
      status: "warn" as const,
      description: `Character substitution patterns detected: ${substitutionCount} patterns`,
      scoreImpact: 15,
    });
    obfuscationScore += 2;
  }

  // 4. Leet Speak Detection
  const leetPatterns = {
    '4': 'a', '@': 'a',
    '8': 'b',
    '3': 'e', '€': 'e',
    '1': 'i', '!': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't',
    '2': 'z',
  };

  let leetScore = 0;
  let leetDecoded = input.toLowerCase();
  
  for (const [leetChar, normalChar] of Object.entries(leetPatterns)) {
    const regex = new RegExp(leetChar, 'g');
    const matches = (leetDecoded.match(regex) || []).length;
    leetScore += matches;
    leetDecoded = leetDecoded.replace(regex, normalChar);
  }

  if (leetScore >= 3) {
    heuristics.push({
      name: "Leet Speak",
      status: "warn" as const,
      description: "Leet speak substitution detected",
      scoreImpact: 20,
    });
    obfuscationScore += 2;
    
    // Check if leet decoding reveals patterns
    if (/[a-z]+\.[a-z]+/i.test(leetDecoded) || /https?:\/\//i.test(leetDecoded)) {
      decodedContent = leetDecoded;
      heuristics.push({
        name: "Leet Decoding Success",
        status: "pass" as const,
        description: "Leet speak revealed recognizable patterns",
        scoreImpact: 0,
      });
      obfuscationScore += 1;
    }
  }

  // 5. Reversed Content Detection
  const reversed = input.split('').reverse().join('');
  if (reversed !== input) {
    // Check if reversed looks more like a normal domain/URL
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(reversed) || /https?:\/\//i.test(reversed)) {
      heuristics.push({
        name: "Reversed Content",
        status: "fail" as const,
        description: "Content appears to be reversed to evade detection",
        scoreImpact: 35,
      });
      obfuscationScore += 4;
      decodedContent = reversed;
    }
  }

  // 6. String Concatenation Patterns
  const concatPatterns = [
    /\+[\'"].*[\'"]/g,  // "string" + "string"
    /\+[a-zA-Z_]\w*/g, // +variable
    /concat\s*\(/gi,   // concat()
    /\.join\s*\(/gi,   // join()
  ];

  let hasConcatenation = false;
  for (const pattern of concatPatterns) {
    if (pattern.test(input)) {
      hasConcatenation = true;
      break;
    }
  }

  if (hasConcatenation) {
    heuristics.push({
      name: "String Concatenation",
      status: "fail" as const,
      description: "Dynamic string construction detected - common in malware",
      scoreImpact: 30,
    });
    obfuscationScore += 3;
  }

  // 7. Multiple Encoding Layers
  let encodingLayers = 0;
  let testContent = input;
  
  // Count how many times we can decode
  for (let i = 0; i < 5; i++) {
    const originalLength = testContent.length;
    
    // Try Base64
    if (/^[A-Za-z0-9+/]{4,}={0,2}$/.test(testContent)) {
      try {
        testContent = Buffer.from(testContent, 'base64').toString('utf8');
        if (testContent !== testContent) encodingLayers++;
      } catch {}
    }
    
    // Try URL decode
    if (/%[0-9A-Fa-f]{2}/.test(testContent)) {
      try {
        testContent = decodeURIComponent(testContent);
        if (testContent.length !== originalLength) encodingLayers++;
      } catch {}
    }
    
    if (testContent.length === originalLength) break;
  }

  if (encodingLayers >= 3) {
    heuristics.push({
      name: "Multiple Encoding Layers",
      status: "fail" as const,
      description: `${encodingLayers} layers of encoding detected - advanced obfuscation`,
      scoreImpact: 40,
    });
    obfuscationScore += 5;
  } else if (encodingLayers >= 2) {
    heuristics.push({
      name: "Multiple Encoding Layers",
      status: "warn" as const,
      description: `${encodingLayers} layers of encoding detected`,
      scoreImpact: 25,
    });
    obfuscationScore += 3;
  }

  // Determine obfuscation level
  let obfuscationLevel: "none" | "low" | "medium" | "high" = "none";
  if (obfuscationScore >= 8) obfuscationLevel = "high";
  else if (obfuscationScore >= 5) obfuscationLevel = "medium";
  else if (obfuscationScore >= 2) obfuscationLevel = "low";

  return {
    heuristics,
    decodedContent,
    obfuscationLevel
  };
}