export async function analyzeUrl(url) {
  try {
    const response = await fetch('http://localhost:5000/predict/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      const text = await response.text();
      console.error("Response body:", text);
      throw new Error('URL analysis failed: ' + response.status);
    }

    const data = await response.json();

    return {
      safetyScore: data.result === 'Legitimate' ? 90 : data.result === 'Phishing' ? 30 : 60,
      domainAge: 'Unknown',
      sslValid: !data.features.NoHttps,
      blacklisted: false,
      suspiciousPatterns: data.features.RandomString ? ['Random string detected'] : [],
      advice: data.result === 'Phishing'
        ? 'This URL may be dangerous. Do not proceed.'
        : 'This URL appears to be safe.'
    };

  } catch (error) {
    console.error("❌ analyzeUrl error:", error);
    return {
      safetyScore: 50,
      sslValid: false,
      domainAge: 'Unknown',
      blacklisted: false,
      suspiciousPatterns: [],
      advice: 'Analysis failed. Please try again.'
    };
  }
}
