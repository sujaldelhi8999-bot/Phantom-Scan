# PhantomScan Shadow Recon
## Target: http://httpbin.org/

### WHOIS
- registrar: Amazon Registrar, Inc.
- creation_date: 2011-06-12 21:57:10
- expiration_date: 2027-06-12 21:57:10
- name_servers: ['ns-1053.awsdns-03.org', 'ns-1555.awsdns-02.co.uk', 'ns-173.awsdns-21.com', 'ns-884.awsdns-46.net']
- registrant_org: c/o whoisproxy.com
- raw: {'status': 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'emails': "['trustandsafety@support.aws.com', '9c56579da75e83e39933a942d2fc192479db7f236462798b9d7aeffb9b1d01af@httpbin.org.whoisproxy.org', '9c56579da75e83e39933a942d2fc19246b68d54b423555e84c254aa134780722@httpbin.org.whoisproxy.org', '9c56579da75e83e39933a942d2fc1924295a3f3fc6df717e7684254ab68a6225@httpbin.org.whoisproxy.org', '9c56579da75e83e39933a942d2fc19241b499c188dc074b909e35a93c26f958b@httpbin.org.whoisproxy.org']", 'dnssec': 'unsigned', 'country': 'US'}

### Google Dorks
- `site:httpbin.org ext:env OR ext:sql OR ext:log OR ext:bak`
- `site:httpbin.org inurl:admin OR inurl:login OR inurl:dashboard`
- `site:httpbin.org "index of /" OR "parent directory"`
- `"httpbin.org" filetype:pdf OR filetype:xlsx OR filetype:docx`
- `site:httpbin.org intitle:"phpinfo" OR intitle:"phpmyadmin"`
- `site:httpbin.org inurl:api OR inurl:rest OR inurl:graphql`

### Disallowed Paths (robots.txt)

### Sitemap URLs

### Exposed Files

### Leaked Emails

### JS Source Maps

### Internal IPs Found