# DkimToolset 🛡️

A powerful .NET-based security toolkit designed to analyze, validate, and simulate vulnerabilities in **DKIM (DomainKeys Identified Mail)** records.
This toolset is specifically built for security researchers and mail administrators to identify weak RSA configurations.

## Key Features

* **Batch-GCD Scanner**: Efficiently detects "Shared Prime" vulnerabilities across thousands of DKIM records using a Product Tree algorithm.
* **Vulnerability Simulation**: Tools to generate weak RSA keys (shared primes or legacy exponents) for testing environments.
* **Security Auditor**: Automatically checks for insecure public exponents (e.g.,  or ).
* **DKIM Parser**: Extracts RSA moduli and exponents directly from DNS-formatted DKIM strings.

## Security Analysis

### 1. Batch-GCD & Shared Primes

If two different DKIM keys share a single prime factor (), an attacker can use the **Batch-GCD algorithm** to factor the modulus () and recover the private key. This tool automates the process:

```csharp
var scanner = new DkimSecurityScanner();
var compromised = scanner.ScanForSharedPrimes(dkimRecords);
// Results contain factored p and q for vulnerable keys
```

### 2. RSA Exponent Validation

The tool checks for the public exponent (). While  () is the industry standard, older or misconfigured keys might use weak values:

| Exponent | Rating | Security Risk |
| --- | --- | --- |
| **3** | ❌ Dangerous | Vulnerable to mathematical root attacks. |
| **17** | ⚠️ Legacy | Outdated, non-standard for modern DKIM. |
| **65537** | ✅ Standard | Optimal balance of security and speed. |

## Getting Started

### Prerequisites

* .NET 10.0 or higher

## Usage Example: Generating a Test Case

To test your own scanner, you can generate a vulnerable key with a legacy exponent ():

```csharp
DkimRsaKeyHelper.GenerateLegacyExponentKey(keySize: 2048);
```

## Disclaimer

This tool is for educational and security auditing purposes only. Only use it on domains and keys you own or have explicit permission to audit.
