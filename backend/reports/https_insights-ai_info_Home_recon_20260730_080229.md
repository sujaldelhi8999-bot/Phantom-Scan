# PhantomScan Shadow Recon
## Target: https://insights-ai.info/Home

### WHOIS
- registrar: 
- creation_date: 
- expiration_date: 
- name_servers: 
- registrant_org: 
- raw: {}

### Google Dorks
- `site:insights-ai.info ext:env OR ext:sql OR ext:log OR ext:bak`
- `site:insights-ai.info inurl:admin OR inurl:login OR inurl:dashboard`
- `site:insights-ai.info "index of /" OR "parent directory"`
- `"insights-ai.info" filetype:pdf OR filetype:xlsx OR filetype:docx`
- `site:insights-ai.info intitle:"phpinfo" OR intitle:"phpmyadmin"`
- `site:insights-ai.info inurl:api OR inurl:rest OR inurl:graphql`

### Disallowed Paths (robots.txt)

### Sitemap URLs

### Exposed Files
- /.env (200)
- /robots.txt (200)
- /.DS_Store (200)
- /config.php (200)
- /.git/HEAD (200)
- /wp-config.php (200)
- /sitemap.xml (200)
- /database.yml (200)

### Leaked Emails

### JS Source Maps

### Internal IPs Found