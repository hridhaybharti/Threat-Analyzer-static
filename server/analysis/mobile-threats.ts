import { HeuristicResult } from "@shared/schema";

interface MobileThreatAnalysis {
  heuristics: HeuristicResult[];
  mobileRisk: "none" | "low" | "medium" | "high";
  threatTypes: string[];
}

export function analyzeMobileThreats(url: URL): MobileThreatAnalysis {
  const heuristics: HeuristicResult[] = [];
  const threatTypes: string[] = [];
  let mobileRisk: "none" | "low" | "medium" | "high" = "none";

  const urlStr = url.toString().toLowerCase();
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname.toLowerCase();

  // 1. SMS Phishing Detection
  const smsPhishingIndicators = [
    'sms', 'text', 'message', 'verify-sms', 'sms-verify', 'txt',
    'mobile-verify', 'phone-verify', '2fa', 'otp', 'one-time',
    'verification-sms', 'secure-sms'
  ];

  const hasSmsPhishing = smsPhishingIndicators.some(indicator => 
    hostname.includes(indicator) || pathname.includes(indicator)
  );

  if (hasSmsPhishing) {
    heuristics.push({
      name: "SMS Phishing Indicator",
      status: "fail" as const,
      description: "SMS-related content detected - potential smishing attempt",
      scoreImpact: 35,
    });
    threatTypes.push("sms_phishing");
    mobileRisk = mobileRisk === "none" ? "medium" : "high";
  }

  // 2. App Store Impersonation
  const officialAppStores = {
    apple: ['apple.com', 'apps.apple.com', 'itunes.apple.com', 'appstore.com'],
    google: ['play.google.com', 'google.com', 'android.com'],
    microsoft: ['microsoft.com', 'store.microsoft.com'],
    amazon: ['amazon.com', 'appstore.amazon.com'],
  };

  const appStoreBrands = ['app-store', 'google-play', 'play-store', 'microsoft-store', 
                        'amazon-appstore', 'apple-app', 'android-app', 'ios-app'];

  // Check for official store URLs
  const isOfficialStore = Object.values(officialAppStores).some(stores =>
    stores.some(store => hostname === store || hostname.endsWith(`.${store}`))
  );

  // Check for app store impersonation
  const hasAppStoreKeywords = appStoreBrands.some(brand => hostname.includes(brand));
  const hasStoreKeywords = ['store', 'app', 'download', 'install'].some(keyword => 
    hostname.includes(keyword)
  );

  if (hasAppStoreKeywords && !isOfficialStore) {
    heuristics.push({
      name: "App Store Impersonation",
      status: "fail" as const,
      description: "Fake app store or app distribution detected",
      scoreImpact: 40,
    });
    threatTypes.push("app_store_impersonation");
    mobileRisk = "high";
  } else if (hasStoreKeywords && !isOfficialStore) {
    heuristics.push({
      name: "Suspicious App Store",
      status: "warn" as const,
      description: "Potential fake app store or app distribution",
      scoreImpact: 25,
    });
    threatTypes.push("suspicious_app_store");
    mobileRisk = mobileRisk === "none" ? "low" : "high";
  }

  // 3. Mobile OS Detection
  const mobileKeywords = ['android', 'ios', 'iphone', 'ipad', 'tablet', 
                         'mobile', 'smartphone', 'app', 'apk', 'ipa', 
                         'sideload', 'jailbreak', 'root'];

  const hasMobileKeywords = mobileKeywords.some(keyword => 
    hostname.includes(keyword) || pathname.includes(keyword)
  );

  // APK file detection (Android malware distribution)
  if (pathname.includes('.apk') || urlStr.includes('.apk')) {
    heuristics.push({
      name: "APK Download",
      status: "fail" as const,
      description: "Direct APK download detected - potential malware distribution",
      scoreImpact: 45,
    });
    threatTypes.push("apk_distribution");
    mobileRisk = "high";
  }

  // IPA file detection (iOS sideloading)
  if (pathname.includes('.ipa') || urlStr.includes('.ipa')) {
    heuristics.push({
      name: "IPA Download",
      status: "fail" as const,
      description: "IPA file download detected - potential iOS malware",
      scoreImpact: 40,
    });
    threatTypes.push("ipa_distribution");
    mobileRisk = "high";
  }

  // Mobile configuration profiles
  if (pathname.includes('.mobileconfig') || urlStr.includes('.mobileconfig')) {
    heuristics.push({
      name: "Mobile Config Profile",
      status: "fail" as const,
      description: "Mobile configuration profile - potential MDM attack",
      scoreImpact: 38,
    });
    threatTypes.push("mobile_config");
    mobileRisk = "high";
  }

  // 4. Mobile Banking Phishing
  const bankingKeywords = ['bank', 'banking', 'mobile-banking', 'm-banking', 
                          'account', 'login', 'signin', 'secure-login'];

  const hasBankingKeywords = bankingKeywords.some(keyword => 
    hostname.includes(keyword) || pathname.includes(keyword)
  );

  if (hasBankingKeywords && hasMobileKeywords) {
    heuristics.push({
      name: "Mobile Banking Phishing",
      status: "fail" as const,
      description: "Mobile banking phishing indicators detected",
      scoreImpact: 42,
    });
    threatTypes.push("mobile_banking_phishing");
    mobileRisk = "high";
  }

  // 5. QR Code Threats
  const qrThreatPatterns = [
    'qr-code', 'qrcode', 'qr-scan', 'scan-qr', 'qr-login',
    'secure-qr', 'qr-verify', 'qr-auth'
  ];

  const hasQRThreats = qrThreatPatterns.some(pattern => 
    hostname.includes(pattern) || pathname.includes(pattern)
  );

  if (hasQRThreats) {
    heuristics.push({
      name: "QR Code Threat",
      status: "warn" as const,
      description: "QR code-based attack vectors detected",
      scoreImpact: 28,
    });
    threatTypes.push("qr_threat");
    mobileRisk = "high";
  }

  // 6. Social Media Mobile Impersonation
  const socialPlatforms = {
    facebook: ['facebook.com', 'fb.com', 'm.facebook.com'],
    instagram: ['instagram.com', 'instagr.am'],
    twitter: ['twitter.com', 'x.com', 'mobile.twitter.com'],
    whatsapp: ['whatsapp.com', 'web.whatsapp.com'],
    telegram: ['telegram.org', 't.me'],
    tiktok: ['tiktok.com', 'm.tiktok.com'],
    snapchat: ['snapchat.com'],
  };

  const socialKeywords = ['facebook', 'instagram', 'twitter', 'whatsapp', 
                        'telegram', 'tiktok', 'snapchat', 'social'];

  const hasSocialKeywords = socialKeywords.some(keyword => hostname.includes(keyword));
  const isOfficialSocial = Object.values(socialPlatforms).some(platforms =>
    platforms.some(platform => hostname === platform || hostname.endsWith(`.${platform}`))
  );

  if (hasSocialKeywords && !isOfficialSocial && hasMobileKeywords) {
    heuristics.push({
      name: "Mobile Social Impersonation",
      status: "fail" as const,
      description: "Mobile-focused social media impersonation",
      scoreImpact: 35,
    });
    threatTypes.push("social_impersonation");
    mobileRisk = mobileRisk === "none" ? "medium" : "high";
  }

  // 7. Mobile Payment Fraud
  const paymentKeywords = ['payment', 'pay', 'wallet', 'transaction', 'transfer',
                         'checkout', 'billing', 'invoice', 'receipt'];

  const hasPaymentKeywords = paymentKeywords.some(keyword => 
    hostname.includes(keyword) || pathname.includes(keyword)
  );

  if (hasPaymentKeywords && hasMobileKeywords) {
    heuristics.push({
      name: "Mobile Payment Fraud",
      status: "fail" as const,
      description: "Mobile payment fraud indicators detected",
      scoreImpact: 38,
    });
    threatTypes.push("payment_fraud");
    mobileRisk = "high";
  }

  // 8. Mobile Device Management (MDM) Attacks
  const mdmPatterns = ['mdm', 'mobile-device-management', 'enroll', 'profile-install',
                      'device-profile', 'enterprise', 'supervision'];

  const hasMDMPatterns = mdmPatterns.some(pattern => 
    hostname.includes(pattern) || pathname.includes(pattern)
  );

  if (hasMDMPatterns) {
    heuristics.push({
      name: "MDM Attack Vector",
      status: "fail" as const,
      description: "Mobile Device Management attack indicators",
      scoreImpact: 40,
    });
    threatTypes.push("mdm_attack");
    mobileRisk = "high";
  }

  // 9. Push Notification Abuse
  const pushPatterns = ['push', 'notification', 'alert', 'message-push', 
                       'mobile-push', 'push-service'];

  const hasPushPatterns = pushPatterns.some(pattern => 
    hostname.includes(pattern) || pathname.includes(pattern)
  );

  if (hasPushPatterns && !isOfficialStore) {
    heuristics.push({
      name: "Push Notification Abuse",
      status: "warn" as const,
      description: "Potential push notification abuse vector",
      scoreImpact: 22,
    });
    threatTypes.push("push_abuse");
    mobileRisk = mobileRisk === "none" ? "medium" : mobileRisk;
  }

  // 10. Mobile Browser Exploits
  const exploitPatterns = ['exploit', 'vulnerability', ' CVE-', 'zero-day',
                         'browser-exploit', 'mobile-exploit'];

  const hasExploitPatterns = exploitPatterns.some(pattern => 
    hostname.includes(pattern) || pathname.includes(pattern)
  );

  if (hasExploitPatterns) {
    heuristics.push({
      name: "Mobile Exploit",
      status: "fail" as const,
      description: "Mobile browser or OS exploit indicators",
      scoreImpact: 45,
    });
    threatTypes.push("mobile_exploit");
    mobileRisk = "high";
  }

  // 11. Cryptocurrency Mobile Scams
  const cryptoPatterns = ['crypto', 'bitcoin', 'ethereum', 'wallet-crypto',
                        'crypto-wallet', 'blockchain', 'altcoin'];

  const hasCryptoPatterns = cryptoPatterns.some(pattern => 
    hostname.includes(pattern) || pathname.includes(pattern)
  );

  if (hasCryptoPatterns && hasMobileKeywords) {
    heuristics.push({
      name: "Mobile Crypto Scam",
      status: "fail" as const,
      description: "Mobile cryptocurrency fraud indicators",
      scoreImpact: 38,
    });
    threatTypes.push("crypto_scam");
    mobileRisk = "high";
  }

  return {
    heuristics,
    mobileRisk,
    threatTypes
  };
}

// Detect mobile-specific phishing campaigns
export function detectMobilePhishingCampaign(url: URL): HeuristicResult | null {
  const analysis = analyzeMobileThreats(url);
  
  const campaignIndicators = [
    analysis.threatTypes.includes("sms_phishing"),
    analysis.threatTypes.includes("mobile_banking_phishing"),
    analysis.threatTypes.includes("app_store_impersonation")
  ];

  if (campaignIndicators.filter(Boolean).length >= 2) {
    return {
      name: "Mobile Phishing Campaign",
      status: "fail" as const,
      description: "Multiple mobile phishing indicators detected - coordinated attack likely",
      scoreImpact: 50,
    };
  }

  return null;
}