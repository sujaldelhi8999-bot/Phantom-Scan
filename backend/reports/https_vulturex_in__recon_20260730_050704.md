# PhantomScan Shadow Recon
## Target: https://vulturex.in/

### WHOIS
- registrar: GoDaddy.com, LLC
- creation_date: [datetime.datetime(2026, 2, 27, 20, 27, 15, 762000), datetime.datetime(2026, 2, 27, 20, 27, 15)]
- expiration_date: [datetime.datetime(2027, 2, 27, 20, 27, 15, 762000), datetime.datetime(2027, 2, 27, 20, 27, 15)]
- name_servers: ['ns09.domaincontrol.com', 'ns10.domaincontrol.com']
- registrant_org: 
- raw: {'status': "['clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientRenewProhibited https://icann.org/epp#clientRenewProhibited']", 'emails': 'abuse@godaddy.com', 'country': 'IN', 'dnssec': 'unsigned'}

### Google Dorks
- `site:vulturex.in ext:env OR ext:sql OR ext:log OR ext:bak`
- `site:vulturex.in inurl:admin OR inurl:login OR inurl:dashboard`
- `site:vulturex.in "index of /" OR "parent directory"`
- `"vulturex.in" filetype:pdf OR filetype:xlsx OR filetype:docx`
- `site:vulturex.in intitle:"phpinfo" OR intitle:"phpmyadmin"`
- `site:vulturex.in inurl:api OR inurl:rest OR inurl:graphql`

### Disallowed Paths (robots.txt)

### Sitemap URLs

### Exposed Files
- /database.yml (200)
- /.git/HEAD (200)
- /robots.txt (200)
- /wp-config.php (200)
- /.DS_Store (200)
- /config.php (200)
- /.env (200)
- /sitemap.xml (200)

### Leaked Emails

### JS Source Maps

### Internal IPs Found