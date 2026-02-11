(async () => {
  try {
    const res = await fetch('http://localhost:5000/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'domain', input: 'youtube.com' }),
    });

    if (!res.ok) {
      console.error('Server returned', res.status);
      const txt = await res.text();
      console.error(txt);
      process.exit(1);
    }

    const data = await res.json();
    console.log('=== API Result Summary ===');
    console.log('riskScore:', data.riskScore);
    console.log('riskLevel:', data.riskLevel);
    console.log('summary:', data.summary);
    console.log('details.threatIntelligence present:', !!(data.details && data.details.threatIntelligence));
    console.log('details.confidence:', data.details && data.details.confidence);
    console.log('signal_count:', data.details && data.details.signal_count);
    console.log('threatIntelligence:', JSON.stringify(data.details && data.details.threatIntelligence, null, 2));
  } catch (err) {
    console.error('Request failed:', err);
    process.exit(1);
  }
})();
