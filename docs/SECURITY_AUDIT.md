# CSAR - Security Audit and Proposed Improvements (Updated)

## 1. Overview
This document contains a high-level security audit of the current CSAR API Gateway and Coordinator codebase, focusing on cryptography, secrets management, network security, and potential vulnerabilities. It also outlines recommended improvements for hardening the project.

**Note:** This audit reflects recent security patches resolving previously identified critical vulnerabilities related to IP spoofing, logging, and TLS enforcement in production.

## 2. Security Audit Findings

### 2.1 Cryptography and Secret Management (KMS)
- **Strengths:** 
  - Centralized secret management with external KMS via Yandex Cloud API.
  - Good support for fetching tokens over gRPC.
  - Configuration files don't store plaintext secrets; they use references and KMS key IDs.
- **Weaknesses:**
  - **Memory Persistence:** Tokens decrypted via `provider.Decrypt` remain in memory as normal Go strings and byte slices. They are cached in `AuthInjector` if `serve_stale` is used and pushed into HTTP headers. Go's garbage collector doesn't guarantee immediate memory wiping, potentially leaving plaintexts exposed in heap dumps.
  - **Replay & Stale Tokens:** The coordinator pushes an `encrypted_token`, but if there's no expiration or proactive rotation, it's vulnerable to long-term exposure.
  - **Metadata SSRF Exposure:** The `metadata_url` in Yandex KMS implementation is hardcoded to `http://169.254.169.254/...`. While standard for GCP/Yandex, in containerized environments (like Kubernetes) without strict network policies, an SSRF vulnerability elsewhere in the app or upstream backend could lead to token extraction.

### 2.2 Network Security and Transport
- **Strengths:**
  - **mTLS Enforced:** Enforced optionally (`RequireMTLSForCoordinator`) and implemented with proper Common Name (CN) and Subject Alternative Name (SAN) validation.
  - **Strict Production Checks:** `InsecureSkipVerify` is strongly forbidden in `prod` configurations, ensuring backends are safely validated against MITM attacks.
  - **Anti-Spoofing IP Extraction:** The router handles `X-Forwarded-For` securely by extracting the rightmost IP, correctly trusting the immediate proxy rather than arbitrarily injected client headers.
- **Weaknesses:**
  - **Lack of granular trusted proxies:** While extracting the rightmost IP from `X-Forwarded-For` is secure for a single-proxy setup, deep proxy chains might require parsing based on an explicitly defined `trusted_proxy_cidrs` list to ensure the true client IP is resolved safely.

### 2.3 Rate Limiting and DoS
- **Weaknesses:**
  - **Global Quotas only:** Traffic configurations (`TrafficConfig`) use global RPS and Burst limits per route. An attacker can consume the entire route's quota, causing a Denial of Service (DoS) for all legitimate users. There is currently no per-IP or per-Client API key rate limiting logic.

### 2.4 Logging and Telemetry
- **Strengths:**
  - **Sensitive Data Redaction:** Uses `logging.Secret` and `RedactingHandler` to actively scrub predefined sensitive keys (`Authorization`, `Bearer`, `Token`, `Password`, `Key`) from standard logs, providing defense-in-depth against accidental credential leakage.

---

## 3. Proposed Improvements

### Immediate Action Items (High Priority)
1. **Per-Client Rate Limiting:**
   - Enhance the `TrafficConfig` to support `limit_by: "ip"` or `limit_by: "header"`. Distribute per-IP buckets across the cluster or manage them locally to prevent single-actor DoS attacks.

2. **Secure Memory Handling for Tokens:**
   - Instead of storing `string` tokens in `staleCache`, utilize byte arrays that are wiped (e.g., overwriting with `0x00`) when replaced or expired, or consider using libraries like `awnumar/memguard` for storing sensitive plaintexts in memory.

### Medium Term Items
3. **Automated Secret Rotation (Coordinator):**
   - Add functionality for the coordinator to rotate the KMS keys or the tokens periodically without requiring restarts, and explicitly signal routers to drop cached `stale_serve` entries by incrementing `token_version`.

4. **Enhance `X-Forwarded-For` Parsing:**
   - Allow configuration of `trusted_proxy_cidrs` to safely traverse proxy chains by dropping known proxies from the right-to-left list of IPs.

### Long Term Items
5. **SSRF Outbound Protections:**
   - Restrict outbound backend requests to ensure they do not accidentally or maliciously hit internal metadata endpoints (e.g., `169.254.169.254`, `10.0.0.0/8`, etc.) unless explicitly whitelisted in a proxy egress ruleset. 
   
6. **Audit Logging Service:**
   - Create an isolated logging mechanism (separate from standard application logs) specifically for auditing security events: Token decryptions, Unauthorized access attempts, Rate limit triggers, and Coordinator mTLS cert rejections. 
