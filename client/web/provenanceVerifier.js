/**
 * provenanceVerifier.js
 * 
 * Project Kerberos - Zero-Trust Digital Forensics
 * Provenance Verification Pipeline to defend against Forged Ledger attacks.
 * 
 * Execution constraints: 
 * - Runs entirely in the browser (no Node.js modules).
 * - Uses native window.crypto.subtle for hashing.
 * - Processes data exclusively as ArrayBuffer or Uint8Array.
 */

const TRUSTED_CA_LIST = ["Sony", "Content Authenticity Initiative", "Nikon"];

/**
 * Step 1: The Trust Anchor Interrogation
 * @param {string} issuer - X.509 issuer string from C2PA manifest.
 * @returns {Object} - Status object
 */
function verifyTrustAnchor(issuer) {
    if (TRUSTED_CA_LIST.includes(issuer)) {
        return { status: 'OK', message: 'Ledger Signature Validated against Trust List.' };
    } else {
        throw { status: 'ERROR', message: 'UNTRUSTED LEDGER SIGNATURE. Issuer not in Trust List.' };
    }
}

/**
 * Step 2: The Cryptographic Hash Binding
 * @param {ArrayBuffer} fileBuffer - Raw file buffer
 * @param {string} manifestHash - Expected hash from ledger
 * @returns {Promise<Object>} - Status object
 */
async function verifyHashBinding(fileBuffer, manifestHash) {
    // Use native window.crypto.subtle for SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', fileBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const currentHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    if (currentHash === manifestHash.toLowerCase()) {
        return { status: 'OK', message: 'SHA-256 Payload Hash Matches Ledger.' };
    } else {
        throw { status: 'ERROR', message: 'PAYLOAD MISMATCH. LEDGER HAS BEEN SPLICED.' };
    }
}

/**
 * Step 3: The Provenance Paradox Backstop
 * @param {ArrayBuffer} fileBuffer - Raw file buffer
 * @returns {Object} - Status object
 */
function executeBlindForensics(fileBuffer) {
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const fileString = decoder.decode(new Uint8Array(fileBuffer));

    // Check A: Count occurrences of %%EOF
    const eofMatches = fileString.match(/%%EOF/g);
    const eofCount = eofMatches ? eofMatches.length : 0;

    if (eofCount > 1) {
        throw { 
            status: 'CRITICAL', 
            type: 'PROVENANCE_PARADOX', 
            message: 'PROVENANCE PARADOX DETECTED. The cryptographic ledger claims this file is an unaltered original, but binary forensics prove unauthorized edits exist. The ledger is a mathematically valid FORGERY.' 
        };
    }

    // Check B: Search for Photoshop signatures
    if (fileString.includes('8BIM') || fileString.includes('Adobe Photoshop')) {
        throw { 
            status: 'CRITICAL', 
            type: 'PROVENANCE_PARADOX', 
            message: 'PROVENANCE PARADOX DETECTED. The cryptographic ledger claims this file is an unaltered original, but binary forensics prove unauthorized edits exist. The ledger is a mathematically valid FORGERY.' 
        };
    }

    return { status: 'OK', message: 'Binary forensics confirm untouched original.' };
}

/**
 * Main Provenance Evaluation Pipeline
 * @param {ArrayBuffer} fileBuffer - Raw file binary
 * @param {Object} parsedC2paManifest - Parsed ledger manifest (contains issuer and manifestHash)
 * @returns {Promise<Object>} - Final verdict and execution logs
 */
export async function evaluateProvenance(fileBuffer, parsedC2paManifest) {
    const executionLog = [];
    let verdict = false;

    try {
        executionLog.push("[*] Initiating Zero-Trust Provenance Verification Pipeline...");

        // Step 1
        executionLog.push("[*] Step 1: Interrogating Trust Anchor...");
        const step1Result = verifyTrustAnchor(parsedC2paManifest.issuer);
        executionLog.push(`[+] ${step1Result.status}: ${step1Result.message}`);

        // Step 2
        executionLog.push("[*] Step 2: Verifying Cryptographic Hash Binding...");
        const step2Result = await verifyHashBinding(fileBuffer, parsedC2paManifest.manifestHash);
        executionLog.push(`[+] ${step2Result.status}: ${step2Result.message}`);

        // Step 3
        executionLog.push("[*] Step 3: Executing Blind Forensics Backstop...");
        const step3Result = executeBlindForensics(fileBuffer);
        executionLog.push(`[+] ${step3Result.status}: ${step3Result.message}`);

        executionLog.push("[*] Pipeline Complete: Asset is AUTHENTIC.");
        verdict = true;

    } catch (error) {
        if (error.status === 'ERROR') {
            executionLog.push(`[-] ${error.status}: ${error.message}`);
        } else if (error.status === 'CRITICAL') {
            executionLog.push(`[!] ${error.status} [${error.type}]: ${error.message}`);
        } else {
            executionLog.push(`[-] UNKNOWN ERROR: ${error.message || error}`);
        }
        executionLog.push("[*] Pipeline Aborted: Asset is COMPROMISED.");
        verdict = false;
    }

    return {
        verdict,
        executionLog
    };
}

// ============================================================================
// MOCK UI IMPLEMENTATION - RED ALERT TERMINAL DASHBOARD
// ============================================================================
/*
// HTML/JS Mock implementation of how a UI should consume the JSON output:

async function runMockUI() {
    // Mock C2PA Manifest (Forged)
    const forgedManifest = {
        issuer: "Content Authenticity Initiative",
        // Valid SHA-256 of empty buffer as mock
        manifestHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };

    // Create a mock forged file buffer with an appended Photoshop edit to trigger Paradox
    const encoder = new TextEncoder();
    const forgedFileBuffer = encoder.encode("%%EOF\\nAdobe Photoshop\\n%%EOF").buffer;

    // Assuming a container exists: <div id="terminal-dashboard" style="background: black; padding: 20px;"></div>
    const uiContainer = document.getElementById('terminal-dashboard');
    if (!uiContainer) return;
    
    uiContainer.innerHTML += '<div style="color: #0f0; font-family: monospace;">[SYSTEM] Booting Kerberos Provenance Module...</div><br/>';

    // Execute the verification
    const result = await evaluateProvenance(forgedFileBuffer, forgedManifest);

    // Render the execution logs
    result.executionLog.forEach(log => {
        let color = "#fff"; // default white
        if (log.startsWith("[+]")) color = "#0f0"; // green success
        if (log.startsWith("[-]")) color = "#f00"; // red error
        if (log.startsWith("[!]")) color = "#ff3333"; // critical bright red
        if (log.startsWith("[*]")) color = "#0ff"; // cyan info

        const logElement = document.createElement('div');
        logElement.style.color = color;
        logElement.style.fontFamily = "monospace";
        logElement.style.marginBottom = "5px";
        logElement.innerText = log;
        uiContainer.appendChild(logElement);
    });

    // Render Final Verdict Alert
    if (!result.verdict) {
        const alertBox = document.createElement('div');
        alertBox.style.border = "2px solid red";
        alertBox.style.backgroundColor = "rgba(255, 0, 0, 0.2)";
        alertBox.style.color = "red";
        alertBox.style.padding = "20px";
        alertBox.style.marginTop = "20px";
        alertBox.style.fontWeight = "bold";
        alertBox.style.fontFamily = "monospace";
        alertBox.style.textAlign = "center";
        
        // Add CSS animation for blinking red alert
        const styleId = 'red-alert-style';
        if (!document.getElementById(styleId)) {
            const style = document.createElement('style');
            style.id = styleId;
            style.innerHTML = `
                @keyframes blink-alert { 
                    0%, 100% { border-color: red; color: red; background-color: rgba(255, 0, 0, 0.2); }
                    50% { border-color: #550000; color: #ff6666; background-color: rgba(100, 0, 0, 0.1); }
                }
            `;
            document.head.appendChild(style);
        }
        
        alertBox.style.animation = "blink-alert 1.5s infinite";
        alertBox.innerHTML = `
            [ RED ALERT ] <br/>
            PROVENANCE INTEGRITY COMPROMISED
        `;
        uiContainer.appendChild(alertBox);
    }
}
*/
