# PhantomScan Hindi Report
## Target: http://httpbin.org/

### Target uses cleartext HTTP
**1. Kya hai yeh? (Simple Hindi mein)**
Iska matlab hai ki website **HTTP** use kar rahi hai, **HTTPS** nahi.
*   **HTTP (Cleartext):** Data (passwords, tokens, cookies) **plain text** mein travel karta hai. Koi bhi beech mein (router, Wi-Fi owner, ISP) padh sakta hai.
*   **HTTPS (Encrypted):** Data **encrypt** hoke travel karta hai. Beech wala sirf garbage characters dekhta hai.

Yahan `http://httpbin.org/` pe **TLS/SSL certificate nahi hai**, isliye connection **secure nahi hai**.

---

**2. Attacker kaise exploit karta hai? (MITM Attack)**
Attacker **Man-in-the-Middle (MITM)** position banata hai:

1.  **Network Sniffing:** Attacker same Wi-Fi pe hai (cafe, airport) ya router compromise kiya hua hai. Woh `tcpdump` ya `Wireshark` se traffic capture karta hai. Usse **Session Cookies**, **Authorization Headers (Bearer tokens)**, **Form Data (username/password)** mil jate hain.
2.  **Session Hijacking:** Attacker cookie churake **Session Hijacking** karta hai — bina password ke victim ke account mein ghus jata hai.
3.  **Data Tampering:** Request/Response modify karta hai. Example: Amount `100` ko `1000` kar diya, ya response mein **XSS** payload inject kar diya.
4.  **Credential Theft:** Agar **Basic Auth** ya login form HTTP pe hai, toh password direct mil jata hai.
5.  **Downgrade/Strip:** Agar site HTTPS bhi support karti hai, toh attacker **SSL Strip** karke user ko forcefully HTTP pe laata hai.

> **Note:** `httpbin.org` ek **testing tool** hai, yahan real user data nahi hota. Lekin production mein yeh **Critical** vulnerability hoti hai.

---

**3. Is platform (http://httpbin.org/) ke liye Exact Fix kya hai?**

**Fix: HTTP band karo, Sirf HTTPS allow karo.**

**Exact Steps for httpbin.org maintainers:**

1.  **Valid TLS Certificate Install Karo:**
    *   **Let's Encrypt** (Free, 90 days) ya koi bhi CA se certificate lo.
    *   `certbot --nginx -d httpbin.org -d www.httpbin.org` run karo.

2.  **Web Server Config (Nginx/Apache) Mein Redirect Dalein:**
    ```nginx
    # HTTP (Port 80) -> HTTPS (Port 443) Permanent Redirect
    server {
        listen 80;
        server_name httpbin.org www.httpbin.org;
        return 301 https://$host$request_uri;
    }

    # HTTPS Server Block
    server {
        listen 443 ssl http2;
        server_name httpbin.org www.httpbin.org;

        ssl_certificate /etc/letsencrypt/live/httpbin.org/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/httpbin.org/privkey.pem;

        # Modern SSL Config (Mozilla SSL Config Generator se lo)
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        # ... baaki location / proxy_pass config ...
    }
    ```

3.  **HSTS Header Add Karo (Browser ko force HTTPS karne ke liye):**
    ```nginx
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    ```

4.  **Secure Cookies Set Karo (Application Code Mein):**
    *   Har `Set-Cookie` header mein `Secure` flag hona chahiye.
    *   Example: `session=abc123; Secure; HttpOnly; SameSite=Strict`

5.  **HSTS Preload List Mein Submit Karo:**
    *   `https://hstspreload.org/` pe domain submit karo. Isse browser pehle se jaanta hai ki ye site **sir
