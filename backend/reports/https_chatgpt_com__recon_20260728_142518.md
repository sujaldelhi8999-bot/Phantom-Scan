# PhantomScan Shadow Recon
## Target: https://chatgpt.com/

### WHOIS
- registrar: MarkMonitor, Inc.
- creation_date: [datetime.datetime(2022, 11, 30, 23, 59, 19), datetime.datetime(2022, 11, 30, 23, 59, 19, tzinfo=datetime.timezone.utc)]
- expiration_date: [datetime.datetime(2026, 11, 30, 23, 59, 19), datetime.datetime(2026, 11, 30, 23, 59, 19, tzinfo=datetime.timezone.utc)]
- name_servers: ['HASSAN.NS.CLOUDFLARE.COM', 'SAVANNA.NS.CLOUDFLARE.COM']
- registrant_org: OpenAI
- raw: {'status': "['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited', 'serverTransferProhibited https://icann.org/epp#serverTransferProhibited', 'serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited', 'clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)', 'clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)', 'clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)', 'serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)', 'serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)', 'serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)']", 'emails': "['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com']", 'dnssec': 'unsigned', 'country': 'US'}

### Google Dorks
- `site:chatgpt.com ext:env OR ext:sql OR ext:log OR ext:bak`
- `site:chatgpt.com inurl:admin OR inurl:login OR inurl:dashboard`
- `site:chatgpt.com "index of /" OR "parent directory"`
- `"chatgpt.com" filetype:pdf OR filetype:xlsx OR filetype:docx`
- `site:chatgpt.com intitle:"phpinfo" OR intitle:"phpmyadmin"`
- `site:chatgpt.com inurl:api OR inurl:rest OR inurl:graphql`

### Disallowed Paths (robots.txt)
- /s/cb_
- /g/
- /auth/logout
- /auth/login?*
- /backend-anon/sentinel/*
- /backend-anon/conversation$
- /account-link/*

### Sitemap URLs

### Exposed Files
- /robots.txt (200)

### Leaked Emails

### JS Source Maps

### Internal IPs Found