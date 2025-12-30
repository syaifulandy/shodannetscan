Persiapan
1. Siapkan file apikey.txt berisikan API shodan atau API Virus Total
2. Siapkan file cidrs.txt berisikan list CIDR yang ingin diambil datanya dari Shodan
3. Siapkan file listip.txt berisikan list IP yang ingin discankan oleh Shodan atau ingin dicari datanya di Shodan
4. Siapkan file org.txt dan port.txt dengan pemisah enter untuk running huntingorgandport.py

Cara Running simple:
1. python3 getallcidrdata.py --cidrs cidrs.txt
2. python3 reqscan.py : Request scan listip.txt
3. python3 subdomain.py --query 'hostname:"*.abc.id"'
4. python3 shodan_getinfoperip.py : Cari info host (port,cve, dll) dari listip.txt
   
