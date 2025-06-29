export async function analyzeEmail(sender, subject, content) {
  const fullText = `${sender} ${subject} ${content}`;

  const response = await fetch('http://localhost:5000/predict/email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email_text: fullText })
  });

  if (!response.ok) {
    throw new Error('Email analysis failed');
  }

  const data = await response.json();

  return {
    safetyScore: data.result === 'Legitimate' ? 85 : 40,
    senderVerified: !sender.toLowerCase().includes('@suspicious.com'),
    phishingIndicators: data.result === 'Phishing' ? ['Suspicious language'] : [],
    urgencyTactics: content.toLowerCase().includes('urgent') || content.toLowerCase().includes('now'),
    suspiciousLinks: (content.match(/https?:\/\/[^\s]+/g) || []).filter(link => link.includes('bit.ly')),
    advice: data.result === 'Phishing'
      ? 'This email seems suspicious. Avoid clicking links or downloading attachments.'
      : 'No major threats detected in this email.'
  };
}
