#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║    SHODAN + GOOGLE DORKS — AUDITORIA DEFENSIVA COMPLETA                    ║
║    Login Pages · Fabricantes · Modelos · Credenciais Padrão                ║
║                                                                              ║
║    1400+ Dorks  |  20 Categorias Login  |  10 Categorias Fabricante        ║
║    110+ Modelos |  300 Credenciais Padrão  |  CVEs Críticos                ║
║                                                                              ║
║    Metodologia: OWASP Top 10 · PTES · GHDB · NIST SP 800-115              ║
║                                                                              ║
║    AVISO LEGAL: USO EXCLUSIVO em auditorias de segurança autorizadas.      ║
║    Usar estes dorks para aceder a sistemas sem autorização constitui crime. ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import json
import datetime
import time
import urllib.parse
import webbrowser
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CORES ANSI
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[33m"

def cor(texto: str, c: str) -> str:
    return f"{c}{texto}{C.RESET}"

LINHA_LARGA = "═" * 80
LINHA_MEDIA = "─" * 80
LINHA_CURTA = "·" * 80

# ─────────────────────────────────────────────────────────────────────────────
# BASE DE DADOS — DORKS DE LOGIN (20 CATEGORIAS / 800+ DORKS)
# ─────────────────────────────────────────────────────────────────────────────

LOGIN_DORKS = {

    "01 — Painéis de Login Genéricos": {
        "descricao": "Qualquer página de login exposta na internet, independentemente do sistema.",
        "risco": "MÉDIO",
        "shodan": [
            'http.title:"Login" port:80,443',
            'http.title:"Admin Login" port:80',
            'http.title:"Administrator Login"',
            'http.title:"User Login" port:80',
            'http.title:"Sign In" port:80,443',
            'http.title:"Welcome - Please Sign In"',
            'http.title:"Secure Login" port:443',
            'http.html:"username" http.html:"password" port:80',
            'http.html:"input type password" port:80',
            'http.html:"Login" http.html:"Remember me"',
            'http.html:"forgot password" port:80,443',
            'http.html:"login.php" port:80',
            'http.html:"form" http.html:"submit" port:80',
            'http.status:200 http.title:"login"',
            'http.title:"login" country:AO',
            'http.title:"login" country:MZ',
            'http.title:"login" country:PT',
            'http.title:"login" country:BR',
            'http.title:"Access" http.html:"password"',
            'http.title:"Portal Login" port:80,443',
        ],
        "google": [
            'intitle:"Login" inurl:login',
            'intitle:"Admin Login" inurl:admin',
            'intitle:"Administrator" inurl:login',
            'intitle:"Login" inurl:/admin/login',
            'intitle:"Sign In" inurl:signin',
            'intitle:"Login" inurl:wp-login.php',
            'intitle:"Login" inurl:index.php',
            'intitle:"Portal" inurl:login',
            'intitle:"Login" inurl:"/cgi-bin/"',
            'inurl:login.asp intitle:"Login"',
            'inurl:login.aspx intitle:"Login"',
            'inurl:login.html intitle:"Login"',
            'inurl:login.htm intitle:"Login"',
            'inurl:login.php intitle:"Login"',
            'inurl:"/auth/login" intitle:"Login"',
            'inurl:"/account/login" intitle:"Login"',
            'inurl:"/user/login" intitle:"Login"',
            'inurl:"/session/new" intitle:"Sign In"',
            'inurl:"/signin" intitle:"Sign In"',
            'inurl:"/authenticate" intitle:"Login"',
        ],
        "credenciais": [],
        "nota": "Para maior precisão, adiciona country:AO ou org:\"sua_empresa\" no Shodan.",
    },

    "02 — Painéis de Administração Web": {
        "descricao": "Painéis admin de servidores, hosting, CMS e infraestrutura.",
        "risco": "ALTO",
        "shodan": [
            'http.title:"Admin Panel" port:80,443',
            'http.title:"Control Panel" port:80',
            'http.title:"Dashboard" http.html:"login"',
            'http.title:"Management Console"',
            'http.title:"Web Admin" port:80',
            'http.title:"phpMyAdmin" port:80',
            'http.title:"cPanel Login" port:2082',
            'http.title:"Plesk" port:8443',
            'http.title:"Webmin Login" port:10000',
            'http.title:"ISPConfig" port:8080',
            'http.title:"DirectAdmin" port:2222',
            'http.title:"WHM Login" port:2086',
            'http.title:"Virtualmin" port:10000',
            'http.title:"HestiaCP" port:8083',
            'http.title:"Ajenti" port:8000',
            'port:2082 http.title:"cPanel"',
            'port:8443 http.title:"Plesk"',
            'port:10000 http.title:"Webmin"',
            'port:2222 http.title:"DirectAdmin"',
            'http.title:"Ajenti" port:8000',
        ],
        "google": [
            'intitle:"phpMyAdmin" inurl:index.php',
            'intitle:"cPanel" inurl:2083',
            'intitle:"Plesk" inurl:8443',
            'intitle:"Webmin" inurl:10000',
            'intitle:"DirectAdmin" inurl:2222',
            'intitle:"WHM" inurl:2086',
            'intitle:"ISPConfig" inurl:login',
            'intitle:"HestiaCP" inurl:login',
            'intitle:"Virtualmin" inurl:login',
            'intitle:"Ajenti" inurl:login',
            'intitle:"Admin Panel" inurl:admin/login',
            'intitle:"Control Panel" inurl:cpanel',
            'intitle:"Dashboard" inurl:dashboard/login',
            'intitle:"Admin" inurl:"/wp-admin/"',
            'intitle:"Admin" inurl:"/administrator/"',
            'inurl:"/admin" intitle:"login" -"no results"',
            'inurl:"/manager/html" Apache Tomcat',
            'intitle:"Tomcat Manager" inurl:manager',
            'inurl:"/phpmyadmin/" intitle:"phpMyAdmin"',
            'inurl:"/pma/" intitle:"phpMyAdmin"',
        ],
        "credenciais": [
            "phpMyAdmin: root/(vazia) ou admin/admin",
            "cPanel: admin/admin",
            "Webmin: root/(password do sistema)",
            "Ajenti: root/admin",
        ],
        "nota": "phpMyAdmin e cPanel expostos sem HTTPS: credenciais em texto claro.",
    },

    "03 — Routers e Equipamentos de Rede": {
        "descricao": "Routers, switches, firewalls com interface web.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"Router Login" port:80',
            'http.title:"Wireless Router" http.html:"login"',
            'http.title:"ADSL Router" port:80',
            'http.title:"DSL Router" port:80',
            'http.title:"Gateway Login" port:80',
            'http.html:"routerlogin" port:80',
            'http.title:"RouterOS" port:80',
            'http.title:"MikroTik" port:80',
            'http.title:"FortiGate" port:443',
            'http.title:"pfSense" port:443',
            'http.title:"OPNsense" port:443',
            'http.title:"SonicWall" port:443',
            'http.title:"Cisco" http.html:"login"',
            'http.title:"TP-LINK" port:80',
            'http.title:"D-Link" http.html:"login"',
            'http.title:"NETGEAR" port:80',
            'http.title:"Huawei" http.html:"login"',
            'http.title:"ZTE" http.html:"login"',
            'http.title:"Ubiquiti" http.html:"login"',
            'http.title:"UniFi" port:8443',
        ],
        "google": [
            'intitle:"Router Login" inurl:login',
            'intitle:"ADSL Router" inurl:login',
            'intitle:"Wireless Router" login admin',
            'intitle:"TP-LINK" inurl:login',
            'intitle:"D-Link" inurl:login',
            'intitle:"NETGEAR" inurl:login',
            'intitle:"Linksys" inurl:setup.cgi',
            'intitle:"MikroTik RouterOS" login',
            'intitle:"pfSense" inurl:index.php',
            'intitle:"OPNsense" inurl:login',
            'intitle:"FortiGate" inurl:login',
            'intitle:"SonicWall" inurl:main',
            'intitle:"Cisco" inurl:login router',
            'intitle:"Huawei" inurl:login router',
            'intitle:"ZTE" inurl:login router',
            'intitle:"UniFi" inurl:login',
            'intitle:"Ubiquiti" inurl:login',
            'inurl:"/userRpm/LoginRpm.htm"',
            'inurl:"/login.asp" router',
            'inurl:"/cgi-bin/luci" router',
        ],
        "credenciais": [
            "TP-Link / D-Link / NETGEAR: admin/admin",
            "MikroTik: admin/(vazia)",
            "pfSense: admin/pfsense",
            "OPNsense: root/opnsense",
            "Cisco: cisco/cisco",
            "Huawei: admin/Admin@123",
        ],
        "nota": "Routers expõem a totalidade do tráfego da rede. Credenciais padrão admin/admin são universais.",
    },

    "04 — Câmeras IP e Sistemas CCTV": {
        "descricao": "Câmeras IP, DVRs, NVRs e sistemas de vigilância expostos.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"DVR Login" port:80',
            'http.title:"NVR Login" port:80',
            'http.title:"IP Camera" http.html:"login"',
            'http.title:"Network Camera" http.html:"login"',
            'http.title:"Live View" http.html:"login"',
            'http.title:"IPCam" port:80',
            'http.title:"Hikvision" port:80',
            'http.title:"Dahua" port:80',
            'http.title:"NetSurveillance WEB"',
            'http.title:"AXIS" http.html:"login"',
            'http.title:"Foscam" port:88',
            'http.html:"DVR Login" port:80',
            'http.html:"iVMS" http.html:"login"',
            'http.title:"CCTV" http.html:"login"',
            'http.html:"videoserver" port:80',
            'port:554 has_screenshot:true',
            'port:8000 http.title:"DVR"',
            'port:37777 has_screenshot:true',
            'port:8080 http.title:"camera"',
            'http.html:"cam_login" port:80',
        ],
        "google": [
            'intitle:"DVR Login" inurl:login',
            'intitle:"NVR Login" admin',
            'intitle:"IP Camera" inurl:login',
            'intitle:"Network Camera" login',
            'intitle:"Hikvision" inurl:login',
            'intitle:"Dahua" inurl:login',
            'intitle:"NetSurveillance WEB"',
            'intitle:"AXIS" "Live View" login',
            'inurl:"/doc/page/login.asp"',
            'inurl:"/cgi-bin/viewer/video.jpg"',
            'inurl:"ViewerFrame?Mode="',
            'inurl:"/view/viewer_index.shtml"',
            'inurl:"/cgi-bin/snapshot.cgi"',
            'inurl:"/webcam/index.html" live',
            'intitle:"Foscam" inurl:login',
            'inurl:":8000/login" DVR',
            'inurl:"/ISAPI/Security" Hikvision',
            'intitle:"CCTV" inurl:login admin',
            'inurl:"/RPC2_Login" Dahua',
            'inurl:"/cgi-bin/login.cgi" camera',
        ],
        "credenciais": [
            "Hikvision: admin/12345",
            "Dahua: admin/admin",
            "Foscam: admin/(vazia)",
            "Axis: root/pass",
            "DVRs genéricos: admin/admin ou admin/1234",
        ],
        "nota": "port:554 has_screenshot:true é o dork mais poderoso — retorna streams de vídeo em tempo real.",
        "cves": ["CVE-2021-36260 (Hikvision RCE crítico sem autenticação)"],
    },

    "05 — Servidores e Virtualização": {
        "descricao": "Hipervisores, BMC (iDRAC, iLO, IPMI), painéis de gestão.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"VMware ESXi" port:443',
            'http.title:"vCenter" port:443',
            'http.title:"Proxmox VE" port:8006',
            'http.title:"XenServer" port:443',
            'http.title:"KVM" http.html:"login"',
            'http.title:"iDRAC" port:443',
            'http.title:"iLO" port:443',
            'http.title:"IPMI" port:443',
            'http.title:"Supermicro IPMI"',
            'http.title:"Webmin" port:10000',
            'http.title:"Cockpit" port:9090',
            'http.title:"Ajenti" port:8000',
            'port:8006 http.title:"Proxmox"',
            'port:9090 http.title:"Cockpit"',
            'port:902 product:"VMware"',
            'port:443 ssl.cert.subject.cn:"idrac"',
            'port:443 ssl.cert.subject.cn:"ilo"',
            'port:443 http.html:"VMware"',
            'http.title:"Nutanix" port:9440',
            'http.title:"oVirt" port:443',
        ],
        "google": [
            'intitle:"VMware ESXi" login',
            'intitle:"VMware vCenter" login',
            'intitle:"Proxmox VE" login',
            'intitle:"Proxmox" inurl:8006',
            'intitle:"XenCenter" login',
            'intitle:"Dell iDRAC" login',
            'intitle:"HP iLO" login',
            'intitle:"Supermicro IPMI" login',
            'intitle:"Cockpit" inurl:9090',
            'intitle:"Ajenti" inurl:8000',
            'intitle:"Nutanix" inurl:9440',
            'intitle:"oVirt" inurl:login',
            'inurl:"/ui/" VMware login',
            'inurl:"/login.html" iDRAC',
            'inurl:"/cgi/login.cgi" IPMI',
            'inurl:"/login/" HP iLO',
            'inurl:":8006/#v1:0" Proxmox',
            'inurl:"/redfish/v1" BMC',
            'inurl:"/data/login" idrac ilo',
            'filetype:cfg "VMware" password',
        ],
        "credenciais": [
            "VMware ESXi: root/(vazia) — em instalações rápidas",
            "Proxmox VE: root@pam/(vazia)",
            "Dell iDRAC: root/calvin",
            "HP iLO: administrator/(única por servidor)",
            "Supermicro IPMI: ADMIN/ADMIN",
        ],
        "nota": "BMC com credenciais padrão dão controlo total do servidor físico — independente do SO.",
        "cves": ["CVE-2021-21985 (VMware vCenter RCE)", "CVE-2013-4786 (IPMI Cipher 0 bypass)"],
    },

    "06 — Bases de Dados e Painéis DB": {
        "descricao": "Painéis de gestão de BD com interface web, frequentemente sem autenticação.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"phpMyAdmin" port:80',
            'http.title:"Adminer" port:80',
            'http.title:"pgAdmin" port:80',
            'http.title:"MongoDB Express" port:8081',
            'http.title:"RedisInsight" port:8001',
            'http.title:"Kibana" port:5601',
            'http.title:"Elasticsearch" port:9200',
            'http.title:"CouchDB" port:5984',
            'http.title:"InfluxDB" port:8086',
            'http.title:"Grafana" port:3000',
            'http.title:"Neo4j Browser" port:7474',
            'http.title:"RethinkDB" port:8080',
            'port:27017 product:"MongoDB"',
            'port:6379 product:"Redis"',
            'port:5984 product:"CouchDB"',
            'port:3306 product:"MySQL"',
            'port:5432 product:"PostgreSQL"',
            'port:9200 product:"Elasticsearch"',
            'port:5601 http.title:"Kibana"',
            'port:8081 http.title:"mongo-express"',
        ],
        "google": [
            'intitle:"phpMyAdmin" "Welcome to phpMyAdmin"',
            'intitle:"phpMyAdmin" inurl:/phpmyadmin/',
            'intitle:"Adminer" inurl:adminer.php',
            'intitle:"pgAdmin" inurl:login',
            'intitle:"MongoDB Express" login',
            'intitle:"RedisInsight" inurl:login',
            'intitle:"Kibana" inurl:login',
            'intitle:"Elasticsearch" inurl:9200',
            'intitle:"Grafana" inurl:login',
            'intitle:"Neo4j Browser" inurl:7474',
            'intitle:"InfluxDB" inurl:login',
            'intitle:"CouchDB" "_utils"',
            'inurl:"/_utils/" CouchDB',
            'inurl:"/phpmyadmin" intitle:"login"',
            'inurl:"/pma/" intitle:"phpMyAdmin"',
            'inurl:"/db/adminer" intitle:"Adminer"',
            'inurl:":5601/app/login" Kibana',
            'inurl:":3000/login" Grafana',
            'inurl:":8081" mongo-express',
            'inurl:":9200/_cat/indices"',
        ],
        "credenciais": [
            "MongoDB: sem autenticação por padrão (porta 27017)",
            "Redis: sem requirepass por padrão (porta 6379)",
            "Elasticsearch: elastic/changeme (porta 9200)",
            "MySQL: root/(vazia)",
            "phpMyAdmin: root/(vazia)",
            "Grafana: admin/admin",
        ],
        "nota": "Mongo Express e CouchDB /_utils são painéis sem autenticação por padrão — acesso total via browser.",
    },

    "07 — Sistemas CMS e Plataformas Web": {
        "descricao": "WordPress, Joomla, Drupal, Magento e outros CMS.",
        "risco": "ALTO",
        "shodan": [
            'http.title:"WordPress" http.html:"wp-login"',
            'http.html:"wp-login.php" port:80',
            'http.title:"Joomla" http.html:"login"',
            'http.html:"Joomla" http.html:"login"',
            'http.title:"Drupal" http.html:"login"',
            'http.html:"Drupal" http.html:"login"',
            'http.title:"Magento" http.html:"login"',
            'http.html:"Magento" http.html:"adminhtml"',
            'http.title:"PrestaShop" http.html:"login"',
            'http.title:"OpenCart" http.html:"login"',
            'http.title:"WooCommerce" http.html:"login"',
            'http.title:"Shopify" http.html:"login"',
            'http.html:"typo3" port:80',
            'http.title:"TYPO3" http.html:"login"',
            'http.title:"Moodle" http.html:"login"',
            'http.title:"Django" http.html:"login"',
            'http.html:"Django administration"',
            'http.title:"Laravel" http.html:"login"',
            'http.html:"Rails" http.html:"login"',
            'http.title:"Wix" http.html:"login"',
        ],
        "google": [
            'intitle:"WordPress" inurl:wp-login.php',
            'inurl:wp-login.php intitle:"Log In"',
            'intitle:"Joomla" inurl:administrator',
            'inurl:"/administrator/" intitle:"Joomla"',
            'intitle:"Drupal" inurl:user/login',
            'inurl:"/user/login" intitle:"Drupal"',
            'intitle:"Magento" inurl:admin login',
            'inurl:"/index.php/admin" Magento',
            'intitle:"PrestaShop" inurl:adminpanel',
            'intitle:"OpenCart" inurl:admin/login',
            'intitle:"TYPO3" inurl:typo3/login',
            'intitle:"Moodle" inurl:login',
            'intitle:"Django administration" login',
            'inurl:"/admin/login" Django',
            'intitle:"Laravel" inurl:login',
            'inurl:"/login" intitle:"Sign In" Laravel',
            'intitle:"Shopify" inurl:admin/auth/login',
            'intitle:"osCommerce" inurl:admin/login',
            'intitle:"Concrete5" inurl:login',
            'intitle:"Umbraco" inurl:umbraco/login',
        ],
        "credenciais": [
            "WordPress: admin/admin (muito comum)",
            "Joomla: admin/admin",
            "Drupal: admin/admin",
            "Magento: admin/admin123",
        ],
        "nota": "WordPress /wp-login.php é o caminho de login mais indexado do mundo. Alvo frequente de brute force.",
    },

    "08 — CI/CD, DevOps e Monitoramento": {
        "descricao": "Jenkins, GitLab, Grafana, Prometheus, Portainer e ferramentas DevOps.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"Jenkins" port:8080',
            'http.title:"GitLab" port:80,443',
            'http.title:"Gitea" port:3000',
            'http.title:"Gogs" port:3000',
            'http.title:"Grafana" port:3000',
            'http.title:"Prometheus" port:9090',
            'http.title:"Alertmanager" port:9093',
            'http.title:"Portainer" port:9000',
            'http.title:"Rancher" port:443',
            'http.title:"Kubernetes" port:6443',
            'http.title:"Argo CD" port:443',
            'http.title:"SonarQube" port:9000',
            'http.title:"Nexus" port:8081',
            'http.title:"Artifactory" port:8081',
            'http.title:"Drone CI" port:80',
            'http.title:"Zabbix" port:80',
            'http.title:"Nagios" port:80',
            'http.title:"Datadog" port:443',
            'port:8080 http.title:"Jenkins"',
            'port:9090 http.title:"Prometheus"',
        ],
        "google": [
            'intitle:"Jenkins" "Manage Jenkins"',
            'intitle:"Jenkins" inurl:login',
            'intitle:"GitLab" inurl:users/sign_in',
            'intitle:"Gitea" inurl:login',
            'intitle:"Gogs" inurl:user/login',
            'intitle:"Grafana" inurl:login',
            'intitle:"Prometheus" inurl:targets',
            'intitle:"Portainer" inurl:login',
            'intitle:"Rancher" inurl:login',
            'intitle:"Argo CD" inurl:login',
            'intitle:"SonarQube" inurl:sessions/new',
            'intitle:"Nexus Repository" inurl:login',
            'intitle:"Artifactory" inurl:login',
            'intitle:"Drone" inurl:login CI',
            'intitle:"Zabbix" inurl:login',
            'intitle:"Nagios" inurl:login',
            'inurl:":8080/jenkins" login',
            'inurl:":9000/portainer" login',
            'inurl:":9090/targets" Prometheus',
            'inurl:"/sonarqube/sessions/new"',
        ],
        "credenciais": [
            "Jenkins: admin/admin",
            "Grafana: admin/admin",
            "Zabbix: Admin/zabbix",
            "Portainer: admin/admin",
            "GitLab: root/5iveL!fe (versão antiga)",
        ],
        "nota": "Jenkins sem autenticação: execução de Groovy Script = RCE total no servidor.",
        "cves": ["CVE-2019-1003000 (Jenkins RCE)"],
    },

    "09 — VPN e Acesso Remoto": {
        "descricao": "SSL VPN, gateways de acesso remoto e portais VPN.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"GlobalProtect" port:443',
            'http.title:"SSL VPN" port:443',
            'http.title:"Fortinet SSL VPN" port:443',
            'http.title:"Cisco AnyConnect" port:443',
            'http.title:"Pulse Secure" port:443',
            'http.title:"Citrix" http.html:"login"',
            'http.title:"NetScaler" port:443',
            'http.title:"F5 BIG-IP" port:443',
            'http.title:"OpenVPN" port:943',
            'http.title:"WireGuard" port:51820',
            'http.title:"SoftEther VPN" port:443',
            'http.html:"sslvpn" port:443',
            'http.html:"webvpn" port:443',
            'http.html:"remote access" port:443',
            'port:443 http.title:"VPN Login"',
            'port:8443 http.title:"VPN"',
            'port:10443 http.title:"FortiGate"',
            'vuln:CVE-2019-11510 port:443',
            'vuln:CVE-2019-19781 port:443',
            'vuln:CVE-2018-13379 port:443',
        ],
        "google": [
            'intitle:"GlobalProtect" inurl:login',
            'intitle:"SSL VPN" inurl:login',
            'intitle:"Fortinet SSL VPN" login',
            'intitle:"Cisco AnyConnect" login',
            'intitle:"Pulse Secure" inurl:login',
            'intitle:"Citrix Gateway" login',
            'intitle:"NetScaler" inurl:login',
            'intitle:"F5 BIG-IP" inurl:login',
            'intitle:"OpenVPN" inurl:login',
            'inurl:"/remote/login" SSL VPN',
            'inurl:"/dana-na/auth/url_default/welcome.cgi"',
            'inurl:"/vpn/index.html" login',
            'inurl:"/ssl-vpn/Login/Login" login',
            'filetype:pcf "enc_GroupPwd" VPN',
            'filetype:ovpn "auth-user-pass"',
            'filetype:conf "remote" "proto udp" openvpn',
            'intitle:"Check Point" "Mobile Access"',
            'inurl:"/cgi-bin/welcome" VPN login',
            'inurl:"/portal/login" SSL VPN',
            'intitle:"VPN" "Username" "Password" login',
        ],
        "credenciais": [
            "FortiGate: admin/(vazia)",
            "OpenVPN AS: admin/admin",
            "Cisco AnyConnect: depende do AD",
        ],
        "nota": "CVE-2019-11510 (Pulse Secure) e CVE-2018-13379 (Fortinet): credenciais exfiltradas sem autenticação.",
        "cves": ["CVE-2019-11510", "CVE-2019-19781", "CVE-2018-13379"],
    },

    "10 — SCADA / ICS / Sistemas Industriais": {
        "descricao": "SCADA, HMIs, PLCs e painéis de controlo industrial expostos.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"SCADA" http.html:"login"',
            'http.title:"HMI" http.html:"login"',
            'http.title:"Ignition" port:8088',
            'http.title:"iFIX" http.html:"login"',
            'http.title:"WinCC" http.html:"login"',
            'http.title:"Wonderware" http.html:"login"',
            'http.title:"SIMATIC" http.html:"login"',
            'http.html:"scada" http.html:"login" port:80',
            'http.title:"Process Control" login',
            'port:102 product:"Siemens"',
            'port:502 product:"Modbus"',
            'port:44818 product:"EtherNet/IP"',
            'port:20000 product:"DNP3"',
            'http.title:"Energy Management" login',
            'http.title:"Building Management" login',
            'http.title:"BMS" http.html:"login"',
            'http.title:"SCADA" country:AO',
            'http.title:"DCS" http.html:"login"',
            'http.html:"plc" http.html:"login" port:80',
            'port:102 has_screenshot:true',
        ],
        "google": [
            'intitle:"SCADA" inurl:login',
            'intitle:"Ignition Gateway" login',
            'intitle:"iFIX" inurl:login SCADA',
            'intitle:"WinCC" Siemens login',
            'intitle:"Wonderware" InTouch login',
            'intitle:"Inductive Automation" login',
            'intitle:"SIMATIC" inurl:login',
            'intitle:"HMI" inurl:login industrial',
            'inurl:"/main/ifix" SCADA login',
            'inurl:"/Portal/Portal.mwsl" Siemens',
            'filetype:pdf "S7-300" "default password"',
            'filetype:mdb "scada" "plc" "password"',
            'filetype:cfg "modbus" "ip" "port"',
            'filetype:xml "PLCOpenXML" project',
            'intitle:"Allen-Bradley" login PLC',
            'intitle:"Rockwell" inurl:login',
            'intitle:"ABB" SCADA login',
            'filetype:csv "tag" "plc" "address"',
            '"Process Control" filetype:pdf password',
            'intitle:"Energy Management" login',
        ],
        "credenciais": [
            "Siemens SIMATIC: admin/admin",
            "Inductive Automation Ignition: admin/admin",
            "Wonderware: (sem auth por padrão em versões antigas)",
        ],
        "nota": "Sistemas SCADA/ICS expostos controlam infraestruturas críticas reais. Acesso não autorizado é crime grave.",
        "cves": ["CVE-2019-13945 (Siemens)"],
    },

    "11 — Sistemas de Saúde e Médicos": {
        "descricao": "HIS, PACS, EMR/EHR e equipamentos médicos conectados.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"PACS" http.html:"login"',
            'http.title:"EMR" http.html:"login"',
            'http.title:"EHR" http.html:"login"',
            'http.title:"HIS" http.html:"login"',
            'http.title:"Radiology" http.html:"login"',
            'port:104 product:"DICOM"',
            'port:11112 product:"DICOM"',
            'port:2575 product:"HL7"',
            'http.title:"Centricity" login',
            'http.title:"Cerner" login',
            'http.title:"Epic" http.html:"login"',
            'http.title:"Meditech" login',
            'http.title:"McKesson" login',
            'http.html:"DICOM" http.html:"login"',
            'http.title:"Hospital" http.html:"login"',
            'http.title:"Philips IntelliVue"',
            'http.title:"GE Healthcare" login',
            'http.title:"Merge DICOM" login',
            'port:8080 http.html:"DICOM"',
            'http.title:"Patient Portal" login',
        ],
        "google": [
            'intitle:"PACS" "DICOM" login admin',
            'intitle:"Centricity PACS" login',
            'intitle:"Cerner" inurl:login',
            'intitle:"Epic" inurl:login EHR',
            'intitle:"Meditech" inurl:login',
            'intitle:"McKesson" login',
            'intitle:"Philips IntelliVue" login',
            'intitle:"GE Healthcare" login',
            'intitle:"Orthanc" Explorer login',
            'intitle:"Patient Portal" login',
            'inurl:"/wado?requestType=WADO"',
            'inurl:"/orthanc/" DICOM login',
            'filetype:dcm DICOM medical image',
            'filetype:hl7 patient record',
            '"patient_name" "DOB" filetype:csv',
            'inurl:"/dicom-web/" login medical',
            'intitle:"Electronic Health Record" login',
            'intitle:"Hospital Information System" login',
            'inurl:"/login" hospital EMR EHR',
            'filetype:xml "ClinicalDocument" HL7',
        ],
        "credenciais": [],
        "nota": "DICOM (porta 104) e HL7 (porta 2575) sem autenticação violam RGPD/HIPAA. Dados de pacientes expostos.",
    },

    "12 — Telecomunicações e VoIP": {
        "descricao": "IPBX, sistemas VoIP, OLTs, ONTs e equipamentos de telecomunicações.",
        "risco": "ALTO",
        "shodan": [
            'http.title:"FreePBX" port:80',
            'http.title:"3CX" port:80,443',
            'http.title:"Asterisk" port:80',
            'http.title:"Grandstream" port:80',
            'http.title:"UCM6" http.html:"login"',
            'http.title:"Yealink" port:80',
            'http.title:"Polycom" http.html:"login"',
            'port:5060 product:"SIP"',
            'port:5060 has_screenshot:true',
            'http.title:"FreeSWITCH" login',
            'http.title:"Kamailio" login',
            'http.title:"OpenSIPS" login',
            'port:5038 product:"Asterisk"',
            'http.title:"Huawei OLT" login',
            'http.title:"ZTE OLT" login',
            'http.title:"GPON" http.html:"login"',
            'port:23 banner:"OLT" country:AO',
            'http.title:"Calix" login',
            'port:4569 product:"IAX"',
            'http.title:"IPBX" http.html:"login"',
        ],
        "google": [
            'intitle:"FreePBX" inurl:login',
            'intitle:"3CX" inurl:login',
            'intitle:"Asterisk" inurl:admin login',
            'intitle:"Grandstream UCM" login',
            'intitle:"Yealink" inurl:admin',
            'intitle:"Polycom" inurl:login',
            'intitle:"FreeSWITCH" inurl:login',
            'intitle:"Kamailio" inurl:login',
            'intitle:"OLT" Huawei login GPON',
            'intitle:"GPON" inurl:login',
            'inurl:"/cgi-bin/api.values.get" VoIP',
            'filetype:conf "sip.conf" "secret"',
            'filetype:conf "extensions.conf" context',
            'intitle:"IPBX" inurl:login admin',
            'filetype:txt "sip trunk" "username" "password"',
            'filetype:conf "register =>" asterisk',
            'filetype:xml "SIPAccount" "password"',
            'filetype:csv "Extension" "SIP" "Password"',
            'intitle:"FreePBX" "Administration" login',
            'inurl:"/admin/config.php" FreePBX',
        ],
        "credenciais": [
            "FreePBX: admin/admin",
            "Asterisk AMI: admin/amp111",
            "Grandstream UCM: admin/admin",
            "Yealink: admin/admin",
        ],
        "nota": "FreePBX admin/admin é padrão. Acesso ao IPBX permite escutar chamadas e fazer toll fraud internacional.",
    },

    "13 — Painéis de Hosting e Cloud": {
        "descricao": "cPanel, WHM, Plesk, WHMCS e painéis de hosting.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"cPanel" port:2082,2083',
            'http.title:"Plesk" port:8443',
            'http.title:"DirectAdmin" port:2222',
            'http.title:"WHM" port:2086',
            'http.title:"Virtualmin" port:10000',
            'http.title:"ISPConfig" port:8080',
            'http.title:"HestiaCP" port:8083',
            'http.title:"Froxlor" port:443',
            'http.title:"WHMCS" port:443',
            'http.title:"HostBill" port:443',
            'http.title:"Blesta" port:443',
            'http.title:"BoxBilling" port:443',
            'port:2082 http.title:"cPanel"',
            'port:2086 http.title:"WHM"',
            'port:2222 http.title:"DirectAdmin"',
            'port:8083 http.title:"HestiaCP"',
            'port:8080 http.title:"ISPConfig"',
            'http.title:"WHMCS" http.html:"login"',
            'http.title:"Reseller" http.html:"login"',
            'port:2082 country:AO',
        ],
        "google": [
            'intitle:"cPanel" inurl:2083',
            'intitle:"WHM" inurl:2086',
            'intitle:"Plesk" inurl:8443',
            'intitle:"DirectAdmin" inurl:2222',
            'intitle:"HestiaCP" inurl:8083',
            'intitle:"ISPConfig" inurl:8080',
            'intitle:"Virtualmin" inurl:10000',
            'intitle:"Froxlor" inurl:login',
            'intitle:"WHMCS" inurl:login admin',
            'intitle:"HostBill" inurl:login',
            'intitle:"Blesta" inurl:login',
            'intitle:"BoxBilling" inurl:login',
            'inurl:"/whm" intitle:"WHM Login"',
            'inurl:"/cpanel" intitle:"cPanel"',
            'inurl:":2083" intitle:"cPanel"',
            'inurl:":2086" intitle:"WebHost"',
            'inurl:":8083" HestiaCP login',
            'filetype:sql "whmcs" "password" admin',
            'intitle:"Reseller" hosting login admin',
            'inurl:":8080" ISPConfig login',
        ],
        "credenciais": [
            "cPanel/WHM: admin/admin",
            "WHMCS: admin/admin",
        ],
        "nota": "cPanel e WHM expostos sem HTTPS: credenciais em texto claro. Comprometimento = acesso a todos os sites hospedados.",
    },

    "14 — Controlo de Acesso Físico": {
        "descricao": "Sistemas de controlo de acesso, biometria e gestão de acessos a edifícios.",
        "risco": "ALTO",
        "shodan": [
            'http.title:"ZKTeco" port:80',
            'http.title:"BioStar" port:80',
            'http.title:"Suprema" http.html:"login"',
            'http.title:"Access Control" http.html:"login"',
            'http.title:"Dahua Access" login',
            'http.title:"Hikvision Access" login',
            'http.title:"HID" http.html:"login"',
            'http.title:"Lenel" http.html:"login"',
            'http.title:"Honeywell" "access control"',
            'http.title:"Paxton" http.html:"login"',
            'http.title:"Genetec" login',
            'http.title:"Milestone" login',
            'port:4370 product:"ZKTeco"',
            'http.title:"Time Attendance" login',
            'http.title:"Door Controller" login',
            'http.html:"biometric" http.html:"login"',
            'http.title:"Video Management" login',
            'http.title:"VMS" http.html:"login"',
            'http.title:"Attendance" http.html:"login"',
            'http.title:"CDVI" http.html:"login"',
        ],
        "google": [
            'intitle:"ZKTeco" inurl:login',
            'intitle:"BioStar 2" login',
            'intitle:"Suprema" access control login',
            'intitle:"Access Control" inurl:login admin',
            'intitle:"Dahua" access control login',
            'intitle:"Hikvision Access" login',
            'intitle:"Lenel OnGuard" login',
            'intitle:"Honeywell" access control login',
            'intitle:"Paxton Net2" login',
            'intitle:"Genetec Security Center" login',
            'intitle:"Milestone XProtect" login',
            'inurl:"/zkbiosecurity" login',
            'inurl:"/biostar2" login',
            'inurl:"/cgi-bin/access" login',
            'filetype:mdb "access_control" "card"',
            'filetype:csv "card_number" "pin" user',
            'intitle:"Time Attendance" admin login',
            'intitle:"Attendance Management" login',
            'intitle:"Video Management System" login',
            'intitle:"CDVI" access control login',
        ],
        "credenciais": [
            "ZKTeco: admin/admin123",
            "BioStar: admin/admin",
            "Genetec: Admin/password",
        ],
        "nota": "Sistemas de controlo de acesso físico comprometidos permitem abertura remota de portas e desativação de alarmes.",
        "cves": ["CVE-2019-12276 (ZKTeco SQL Injection)"],
    },

    "15 — Portais Governamentais e Institucionais": {
        "descricao": "Portais de organizações governamentais, autarquias e universidades.",
        "risco": "ALTO",
        "shodan": [
            'http.title:"Login" site:gov.ao',
            'http.title:"Login" country:AO org:"governo"',
            'http.title:"Portal" http.html:"login" country:AO',
            'http.title:"Intranet" http.html:"login" country:AO',
            'http.title:"Login" country:MZ',
            'http.title:"Login" country:PT',
            'http.title:"Login" country:CV',
            'http.title:"Login" country:ST',
            'http.title:"Login" country:GW',
            'http.title:"Login" org:"universidade" country:AO',
            'http.title:"Login" org:"ministerio" country:AO',
            'http.title:"Login" org:"municipio" country:AO',
            'ssl.cert.subject.cn:"*.gov.ao"',
            'ssl.cert.subject.cn:"*.gov.mz"',
            'ssl.cert.subject.cn:"*.gov.pt"',
            'http.title:"Login" org:"TAAG" country:AO',
            'http.title:"Login" org:"Sonangol" country:AO',
            'http.title:"Login" org:"BNA" country:AO',
            'http.title:"Login" org:"ENDIAMA" country:AO',
            'http.title:"Autenticacao" country:AO,PT,MZ',
        ],
        "google": [
            'site:gov.ao intitle:"Login"',
            'site:gov.ao intitle:"Autenticacao"',
            'site:gov.ao inurl:login',
            'site:gov.mz intitle:"Login"',
            'site:gov.pt intitle:"Login"',
            'site:gov.cv intitle:"Login"',
            'site:ac.ao intitle:"Login"',
            'site:edu.ao intitle:"Login"',
            'site:org.ao intitle:"Login"',
            'site:ao intitle:"Intranet" login',
            'site:ao filetype:php inurl:login',
            'site:mz intitle:"Login" portal',
            'site:ao intitle:"Portal" login',
            'site:ao intitle:"Sistema" inurl:login',
            'site:ao intitle:"Gestao" inurl:login',
            'site:ao filetype:aspx inurl:login',
            'site:ao filetype:jsp inurl:login',
            'site:ao inurl:"/admin" login',
            'site:ao inurl:"/gestor" login',
            'site:gov.ao "utilizador" "palavra-passe"',
        ],
        "credenciais": [],
        "nota": "Portais governamentais angolanos (site:gov.ao) frequentemente têm sistemas desatualizados e credenciais fracas.",
    },

    "16 — Ficheiros e Credenciais Expostas": {
        "descricao": "Ficheiros de configuração, logs, backups e documentos com credenciais.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.html:"password" http.html:"username"',
            'http.html:"DB_PASSWORD" port:80',
            'http.html:"config.php" port:80',
            'http.html:".env" port:80',
            'http.title:"Index of" port:80',
            'http.html:"wp-config" port:80',
            'http.html:"login credentials" port:80',
            'http.html:"default password" port:80',
            'http.html:"admin password" port:80',
            'http.html:"root password" port:80',
        ],
        "google": [
            'filetype:env "DB_PASSWORD" "DB_USER"',
            'filetype:env "APP_PASSWORD" "SECRET_KEY"',
            'filetype:cfg "password" "username" login',
            'filetype:ini "password" "user" login',
            'filetype:xml "password" "username" login',
            'filetype:yml "password" "user" login',
            'filetype:json "password" "username"',
            'filetype:txt "admin" "password" login',
            'filetype:log "password" "login failed"',
            'filetype:sql "INSERT INTO users" "password"',
            'filetype:bak "wp-config" "DB_PASSWORD"',
            'filetype:old "config" "password"',
            '"BEGIN RSA PRIVATE KEY" filetype:pem',
            '"BEGIN OPENSSH PRIVATE KEY" filetype:txt',
            'filetype:ppk "PuTTY-User-Key-File"',
            'filetype:kdbx "KeePass" password',
            'filetype:pcf "enc_GroupPwd" VPN',
            'filetype:ovpn "auth-user-pass"',
            'intitle:"index of" "password.txt"',
            'intitle:"index of" "credentials"',
        ],
        "credenciais": [],
        "nota": "Ficheiros .env e config.php expostos contêm frequentemente credenciais de BD, APIs e serviços de terceiros.",
    },

    "17 — Aplicações Empresariais ERP/CRM": {
        "descricao": "SAP, Oracle, Microsoft Dynamics, Odoo e outros sistemas ERP/CRM.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"SAP" http.html:"login"',
            'http.title:"SAP NetWeaver" login',
            'http.title:"Oracle EBS" login',
            'http.title:"Microsoft Dynamics" login',
            'http.title:"Odoo" port:8069',
            'http.title:"SalesForce" login',
            'http.title:"Zoho" http.html:"login"',
            'http.title:"Freshdesk" login',
            'http.title:"Zendesk" login',
            'http.title:"HubSpot" login',
            'http.title:"Pipedrive" login',
            'http.title:"Vtiger" login',
            'http.title:"SugarCRM" login',
            'http.title:"SuiteCRM" login',
            'http.title:"Dolibarr" login',
            'http.title:"ERPNext" port:8000',
            'port:8069 product:"Odoo"',
            'http.title:"Odoo" http.html:"login"',
            'port:8000 http.title:"ERPNext"',
            'http.html:"SAP" http.html:"Anmelden"',
        ],
        "google": [
            'intitle:"SAP NetWeaver" login',
            'inurl:"/sap/bc/gui/sap/its/webgui" login',
            'intitle:"SAP" inurl:login',
            'intitle:"Oracle E-Business Suite" login',
            'intitle:"Microsoft Dynamics" inurl:login',
            'intitle:"Odoo" inurl:login',
            'inurl:":8069/web/login" Odoo',
            'intitle:"ERPNext" inurl:login',
            'inurl:":8000/login" ERPNext',
            'intitle:"SuiteCRM" inurl:login',
            'intitle:"SugarCRM" inurl:login',
            'intitle:"vtiger" inurl:login',
            'intitle:"Dolibarr" inurl:login',
            'intitle:"OpenERP" inurl:login',
            'intitle:"Tryton" inurl:login',
            'filetype:conf "SAP" "password" login',
            'filetype:xml "SAP" "client" "password"',
            'intitle:"TOTVS" inurl:login',
            'intitle:"Sankhya" inurl:login',
            'intitle:"ERP" inurl:login',
        ],
        "credenciais": [
            "SAP: SAP*/06071992 ou DDIC/19920706",
            "Odoo: admin/admin",
            "ERPNext: Administrator/admin",
            "SuiteCRM: admin/admin",
        ],
        "nota": "SAP NetWeaver com credenciais padrão representa risco extremo em organizações.",
    },

    "18 — IoT e Smart Home": {
        "descricao": "Home Assistant, Node-RED, MQTT e dispositivos IoT residenciais.",
        "risco": "MÉDIO",
        "shodan": [
            'http.title:"Home Assistant" port:8123',
            'http.title:"openHAB" port:8080',
            'http.title:"Domoticz" port:8080',
            'http.title:"Node-RED" port:1880',
            'http.title:"ioBroker" port:8081',
            'http.title:"HomeGenie" port:80',
            'http.title:"Vera" port:80',
            'http.title:"Hubitat" port:80',
            'http.title:"SmartThings" login',
            'http.title:"Shelly" port:80',
            'port:1883 product:"MQTT"',
            'port:8883 product:"MQTT"',
            'port:1880 http.title:"Node-RED"',
            'port:8123 http.title:"Home Assistant"',
            'port:8080 http.title:"openHAB"',
            'http.title:"Tuya" http.html:"login"',
            'http.title:"Tasmota" port:80',
            'http.html:"ESP8266" port:80',
            'http.html:"ESP32" http.html:"login"',
            'port:6668 product:"Tuya"',
        ],
        "google": [
            'intitle:"Home Assistant" inurl:login',
            'inurl:":8123/auth/authorize" Home Assistant',
            'intitle:"openHAB" inurl:login',
            'intitle:"Domoticz" inurl:login',
            'intitle:"Node-RED" inurl:admin',
            'inurl:":1880" Node-RED admin',
            'intitle:"ioBroker" inurl:login',
            'intitle:"Vera" home controller login',
            'intitle:"Hubitat" inurl:login',
            'intitle:"Tasmota" inurl:login',
            'intitle:"Shelly" smart home',
            'filetype:yaml "homeassistant" "password"',
            '"configuration.yaml" filetype:yaml password',
            'filetype:json "smartthings" "access_token"',
            'filetype:conf "mqtt" "username" "password"',
            'filetype:conf "openhab" "password"',
            '"MQTT" "username" "password" filetype:conf',
            '"bearer_token" filetype:json smart home',
            'intitle:"ESP" setup wifi password',
            'filetype:yaml "tuya" "secret" smart',
        ],
        "credenciais": [
            "Shelly: admin/(vazia)",
            "Domoticz: admin/domoticz",
            "Node-RED: sem auth por padrão",
        ],
        "nota": "MQTT sem autenticação (porta 1883) expõe mensagens de todos os dispositivos IoT.",
        "cves": ["CVE-2020-27403 (Tuya)"],
    },

    "19 — Storage / NAS / Backup": {
        "descricao": "Synology, QNAP, TrueNAS, Veeam e sistemas de armazenamento.",
        "risco": "CRÍTICO",
        "shodan": [
            'http.title:"Synology" port:5000,5001',
            'http.title:"QNAP" port:8080',
            'http.title:"TrueNAS" port:443',
            'http.title:"FreeNAS" port:443',
            'http.title:"OpenMediaVault" port:80',
            'http.title:"My Cloud" port:80',
            'http.title:"Veeam" port:9443',
            'http.title:"Commvault" port:81',
            'http.title:"Arcserve" port:8015',
            'http.title:"NetApp" port:443',
            'http.title:"Dell EMC" port:443',
            'http.title:"HPE MSA" port:443',
            'port:5000 http.title:"Synology"',
            'port:8080 http.title:"QNAP"',
            'port:9443 http.title:"Veeam"',
            'port:3260 product:"iSCSI"',
            'port:2049 product:"NFS"',
            'port:445 product:"Samba"',
            'http.title:"Asustor" port:8000',
            'http.title:"ReadyNAS" port:443',
        ],
        "google": [
            'intitle:"Synology DiskStation" login',
            'inurl:":5000/webman/login.cgi"',
            'intitle:"QNAP" inurl:login',
            'inurl:":8080/cgi-bin/login" QNAP',
            'intitle:"TrueNAS" inurl:login',
            'intitle:"FreeNAS" inurl:login',
            'intitle:"OpenMediaVault" inurl:login',
            'intitle:"My Cloud" inurl:login WD',
            'intitle:"WD My Cloud" admin',
            'intitle:"Veeam" inurl:login backup',
            'intitle:"Commvault" inurl:login',
            'intitle:"Arcserve" inurl:login',
            'intitle:"NetApp System Manager" login',
            'intitle:"Dell EMC" storage login',
            'inurl:":5001/webman" Synology',
            'inurl:":9443" Veeam login',
            'filetype:xml "backup" "schedule" "password"',
            'filetype:ini "backup" "password" "server"',
            'intitle:"ReadyNAS" inurl:login',
            'site:*.myqnapcloud.com login',
        ],
        "credenciais": [
            "Synology DiskStation: admin/admin",
            "QNAP: admin/admin",
            "Western Digital My Cloud: admin/(vazia)",
            "TrueNAS: root/(definido na instalação)",
        ],
        "nota": "NAS Synology e QNAP foram alvos de ransomware massivo. admin/admin é a credencial padrão universal.",
        "cves": ["CVE-2021-31439 (Synology)", "CVE-2021-28799 (QNAP QLocker)", "CVE-2021-35941 (WD RCE)"],
    },

    "20 — Energia / UPS / PDU": {
        "descricao": "UPS inteligentes, PDUs de datacenter e sistemas de gestão de energia.",
        "risco": "ALTO",
        "shodan": [
            'http.title:"APC" "UPS" port:80',
            'http.title:"Eaton" UPS login',
            'http.title:"Raritan PDU" port:443',
            'http.title:"ServerTech" PDU',
            'http.title:"Tripp Lite" UPS',
            'http.title:"CyberPower" UPS',
            'http.title:"Vertiv" port:443',
            'http.title:"PowerAlert" login',
            'http.title:"Liebert" UPS',
            'http.title:"Schneider UPS" login',
            'port:161 product:"SNMP" ups',
            'port:3000 http.title:"PowerAlert"',
            'port:3052 product:"CyberPower"',
            'http.html:"UPS" http.html:"battery" port:80',
            'http.title:"Network Management Card"',
            'product:"APC" port:80,443',
            'product:"Eaton" UPS port:80',
            'http.title:"Intelligent Power Manager"',
            'http.title:"EcoStruxure" login',
            'http.html:"PDU" http.html:"outlet" port:80',
        ],
        "google": [
            'intitle:"APC Smart-UPS" login',
            'intitle:"APC" "Network Management Card"',
            'intitle:"Eaton" UPS login',
            'intitle:"Raritan PDU" login',
            'intitle:"ServerTech" PDU admin',
            'intitle:"Tripp Lite" inurl:admin',
            'intitle:"CyberPower" UPS login',
            'intitle:"Vertiv" Liebert login',
            'intitle:"PowerAlert" login UPS',
            'inurl:"/NMC/" APC login',
            'inurl:"/ups/index.html" admin',
            'inurl:":3000" PowerAlert login',
            '"snmp community" "public" UPS',
            'intitle:"Intelligent Power Manager" login',
            'intitle:"EcoStruxure" login Schneider',
            'inurl:"/admin/login" ups pdu',
            'filetype:cfg "ups" "snmp" "community"',
            'filetype:ini "powerchute" password',
            'intitle:"PDU" outlet admin login',
            'filetype:mib "UPS-MIB" SNMP',
        ],
        "credenciais": [
            "APC: apc/apc ou admin/admin",
            "Eaton: admin/admin",
            "CyberPower: cyber/cyber",
            "Raritan: admin/raritan",
        ],
        "nota": "UPS com SNMP community 'private': escrita permitida. Permite desligar UPS remotamente — causa downtime físico.",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# BASE DE DADOS — DORKS POR FABRICANTE / MODELO (600+ DORKS)
# ─────────────────────────────────────────────────────────────────────────────

FABRICANTES_DORKS = {

    "ROUTERS & SWITCHES": {

        "Cisco — IOS Router": {
            "creds": "user:cisco  pass:cisco  proto:Telnet/SSH",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Cisco IOS" port:23',
                'product:"Cisco IOS" port:22',
                'banner:"Cisco IOS" port:23',
                'banner:"User Access Verification" port:23',
                'product:"Cisco" http.title:"Login" port:80',
                'product:"Cisco IOS" country:AO',
                'product:"Cisco IOS" country:PT',
            ],
            "google": [
                'intitle:"Cisco IOS" inurl:login',
                'intitle:"Cisco Systems" "User Access Verification"',
                'intitle:"Cisco Router" inurl:admin',
                'filetype:cfg "enable secret" "cisco"',
                'filetype:txt "username cisco" "password cisco"',
                'filetype:conf "ip address" "Cisco IOS"',
                'site:pastebin.com "cisco" "enable secret"',
            ],
            "cves": [],
            "nota": "Telnet porta 23 exposto transmite credenciais em texto claro.",
        },

        "Cisco — ASA Firewall (5505/5510/5520)": {
            "creds": "user:enable  pass:cisco  proto:SSH/ASDM",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Cisco ASA" port:443',
                'http.title:"Cisco ASDM" port:443',
                'product:"Cisco Adaptive Security" port:22',
                'ssl.cert.subject.cn:"*.cisco.com" port:443',
                'product:"Cisco ASA" country:AO,BR,PT',
                'http.html:"ASDM" port:443',
            ],
            "google": [
                'intitle:"Cisco ASDM" login',
                'intitle:"Cisco ASA" "ASDM" inurl:login',
                'filetype:cfg "ASA Version" "enable password"',
                'filetype:txt "Cisco ASA" "enable cisco"',
                'inurl:"/admin/public/index.html" cisco ASA',
                'filetype:cfg "crypto isakmp" "cisco"',
            ],
            "cves": [],
            "nota": "Enable password padrão 'cisco'. ASDM acessível via HTTPS.",
        },

        "Cisco — Linksys WRT54G / E-Series": {
            "creds": "user:admin  pass:admin  proto:HTTP",
            "risco": "ALTO",
            "shodan": [
                'http.title:"Linksys" port:80',
                'product:"Linksys" http.title:"Login"',
                'http.html:"WRT54G" port:80',
                'http.html:"Linksys E-Series" port:80',
                'http.title:"Linksys Smart Wi-Fi"',
                'product:"Cisco Linksys" port:80,8080',
            ],
            "google": [
                'intitle:"Linksys" inurl:"setup.cgi"',
                'intitle:"Linksys" "WRT54G" admin login',
                'intitle:"Linksys E-Series" login',
                'inurl:"/apply.cgi" Linksys',
                'filetype:cfg "Linksys" "passphrase"',
                'intitle:"Linksys Smart Wi-Fi"',
            ],
            "cves": [],
            "nota": "admin/admin. Um dos routers mais vendidos da história.",
        },

        "Cisco — RV320/RV325 VPN Router": {
            "creds": "user:cisco  pass:cisco  proto:HTTPS",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Cisco RV320" port:443',
                'http.title:"RV32" port:443',
                'http.html:"Cisco Small Business" port:443',
                'product:"Cisco RV" port:443,80',
                'vuln:CVE-2019-1652 product:"Cisco RV"',
            ],
            "google": [
                'intitle:"RV320" inurl:login',
                'intitle:"Cisco Small Business" RV320 login',
                'inurl:"/cgi-bin/userLogin.cgi" Cisco',
                'filetype:cfg "Cisco RV320" password',
                'intitle:"RV325" admin login',
            ],
            "cves": ["CVE-2019-1652 (RCE não autenticado)", "CVE-2019-1653 (leitura de ficheiros sem auth)"],
            "nota": "Crítico — RCE e exfiltração de configuração sem autenticação.",
        },

        "Cisco — Catalyst 2960/3750 Switch": {
            "creds": "user:cisco  pass:cisco  proto:Telnet/SSH/HTTP",
            "risco": "ALTO",
            "shodan": [
                'product:"Cisco Catalyst" port:23',
                'banner:"Cisco Catalyst" port:23',
                'http.title:"Catalyst" port:80',
                'product:"Cisco Catalyst 2960" port:22',
                'product:"Cisco Catalyst 3750" port:23',
                'banner:"WS-C2960" port:23',
            ],
            "google": [
                'intitle:"Cisco Catalyst" login',
                'filetype:cfg "Cisco Catalyst 2960"',
                'filetype:txt "interface GigabitEthernet" "Catalyst"',
                'filetype:cfg "spanning-tree" "cisco catalyst"',
                'intitle:"Catalyst 3750" inurl:admin',
                'filetype:txt "enable secret" Catalyst',
            ],
            "cves": [],
            "nota": "Switches Catalyst com Telnet — altamente comum em redes corporativas antigas.",
        },

        "Huawei — AR Series Router": {
            "creds": "user:admin  pass:Admin@123  proto:HTTP/SSH",
            "risco": "ALTO",
            "shodan": [
                'product:"Huawei AR" port:80',
                'http.title:"Huawei AR" login',
                'banner:"Huawei" port:22',
                'product:"Huawei" http.html:"AR1220"',
                'product:"Huawei Router" port:80,443',
                'product:"Huawei" country:AO port:80',
            ],
            "google": [
                'intitle:"Huawei AR" inurl:login',
                'intitle:"Huawei" AR1220 admin',
                'filetype:cfg "Huawei AR" "Admin@123"',
                'intitle:"Huawei" router inurl:admin',
                'filetype:txt "Huawei AR" "password"',
                'site:.ao intitle:"Huawei" router',
            ],
            "cves": [],
            "nota": "Admin@123 é a password padrão da Huawei para dispositivos empresariais.",
        },

        "Huawei — HG8247H / HG8245H GPON ONT": {
            "creds": "user:telecomadmin  pass:admintelecom  proto:HTTP/Telnet",
            "risco": "CRÍTICO",
            "shodan": [
                'http.title:"HG8247" port:80',
                'http.html:"HG8247H" port:80',
                'product:"Huawei HG8247"',
                'http.html:"telecomadmin" port:80',
                'product:"Huawei" "ONT" port:80',
                'http.title:"HG8245" port:80',
                'port:23 banner:"Huawei" GPON',
            ],
            "google": [
                'intitle:"HG8247" telecomadmin login',
                'intitle:"Huawei HG8247" admin',
                'inurl:"/html/index.asp" HG8247',
                'intitle:"HG8245" inurl:login',
                'filetype:cfg "telecomadmin" "admintelecom"',
                'intitle:"GPON ONT" Huawei login',
                'site:.ao intitle:"HG82" login',
            ],
            "cves": [],
            "nota": "Muito comum em Angola. A conta telecomadmin tem mais privilégios que admin.",
        },

        "Huawei — MA5600T / MA5800 OLT": {
            "creds": "user:root  pass:admin  proto:Telnet/SSH",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Huawei MA5600" port:23',
                'banner:"MA5600T" port:23',
                'product:"Huawei OLT" port:22',
                'http.html:"MA5800" port:80',
                'product:"Huawei" "MA5" port:23',
                'banner:"Huawei Versatile Routing Platform"',
            ],
            "google": [
                'intitle:"Huawei MA5600" login',
                'intitle:"Huawei OLT" inurl:admin',
                'filetype:cfg "MA5600T" "root" "admin"',
                'filetype:txt "Huawei MA5800" password',
                'intitle:"GPON OLT" Huawei login',
                'filetype:log "MA5600" authentication',
            ],
            "cves": [],
            "nota": "OLTs Huawei controlam centenas/milhares de clientes GPON. Comprometimento afeta toda a rede.",
        },

        "TP-Link — TL-WR841N / TL-WR940N": {
            "creds": "user:admin  pass:admin  proto:HTTP",
            "risco": "ALTO",
            "shodan": [
                'http.title:"TL-WR841N" port:80',
                'product:"TP-LINK TL-WR841N"',
                'http.html:"TL-WR940N" port:80',
                'product:"TP-LINK" port:80 country:AO',
                'http.html:"TP-LINK Wireless" port:80',
                'product:"TP-LINK" port:80 country:BR',
            ],
            "google": [
                'intitle:"TL-WR841N" inurl:login',
                'intitle:"TP-LINK" "TL-WR841N" admin',
                'inurl:"/userRpm/LoginRpm.htm" TP-LINK',
                'intitle:"TP-LINK" admin password "admin"',
                'filetype:cfg "TP-LINK" "ssid" "password"',
                'site:.ao intitle:"TP-LINK" login',
            ],
            "cves": [],
            "nota": "Um dos routers mais vendidos mundialmente. admin/admin é universalmente conhecido.",
        },

        "MikroTik — RouterOS (hAP/RB series)": {
            "creds": "user:admin  pass:(vazia)  proto:Winbox/SSH/HTTP",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"MikroTik" port:8291',
                'port:8291 product:"MikroTik"',
                'product:"RouterOS" port:22',
                'http.title:"RouterOS" port:80',
                'product:"MikroTik" port:80,8080',
                'product:"MikroTik" country:AO,BR,MZ',
                'port:8291 country:AO',
                'banner:"MikroTik RouterOS" port:23',
            ],
            "google": [
                'intitle:"RouterOS" MikroTik login',
                'intitle:"MikroTik" inurl:winbox',
                'inurl:"/webfig/" MikroTik',
                'filetype:rsc "MikroTik" "password"',
                'filetype:backup "MikroTik" RouterOS',
                'filetype:rsc "/ip firewall" mikrotik',
                'site:.ao intitle:"MikroTik" login',
                'filetype:txt "admin" "MikroTik" password',
            ],
            "cves": [],
            "nota": "Port 8291 é o Winbox. Admin sem password é o padrão de fábrica em TODOS os modelos MikroTik.",
        },

        "D-Link — DIR-615 / DIR-300 / DIR-600": {
            "creds": "user:admin  pass:(vazia)  proto:HTTP",
            "risco": "CRÍTICO",
            "shodan": [
                'http.title:"DIR-615" port:80',
                'http.html:"D-Link DIR-615"',
                'http.title:"DIR-300" port:80',
                'product:"D-Link" port:80',
                'http.html:"D-Link" "DIR-" port:80',
                'product:"D-Link" country:BR,AO port:80',
            ],
            "google": [
                'intitle:"D-Link" "DIR-615" login',
                'intitle:"D-Link" admin inurl:login',
                'inurl:"/login.php" "D-Link DIR"',
                'intitle:"DIR-300" D-Link admin',
                'filetype:cfg "D-Link" "DIR" password',
                'intitle:"D-Link" "DIR-600" login',
            ],
            "cves": ["CVE-2018-10822 (D-Link DSL path traversal)"],
            "nota": "DIR-615/300/600: password VAZIA por padrão! Apenas utilizador admin necessário.",
        },

        "pfSense / OPNsense": {
            "creds": "user:admin  pass:pfsense (ou opnsense)  proto:HTTPS",
            "risco": "ALTO",
            "shodan": [
                'http.title:"pfSense" login',
                'http.html:"pfSense" port:443',
                'http.title:"OPNsense" login',
                'http.html:"OPNsense" port:443',
                'product:"pfSense" port:443',
            ],
            "google": [
                'intitle:"pfSense" inurl:index.php',
                'intitle:"pfSense" login admin',
                'intitle:"OPNsense" login',
                'inurl:"/index.php" "pfSense" login',
                'filetype:xml "pfSense" "bcrypt" password',
            ],
            "cves": [],
            "nota": "pfSense: admin/pfsense. OPNsense: root/opnsense.",
        },
    },

    "CÂMERAS IP / NVR / DVR": {

        "Hikvision — DS-2CD Series": {
            "creds": "user:admin  pass:12345  proto:HTTP/RTSP",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Hikvision" port:80',
                'http.title:"Hikvision" port:80',
                'http.html:"DS-2CD" port:80',
                'product:"Hikvision" has_screenshot:true',
                'port:554 product:"Hikvision"',
                'product:"Hikvision" country:AO,BR,PT',
                'vuln:CVE-2021-36260 product:"Hikvision"',
                'http.html:"DNVRS-Webs" port:80',
            ],
            "google": [
                'intitle:"Hikvision" "DS-2CD" login',
                'intitle:"Hikvision" inurl:login',
                'inurl:"/doc/page/login.asp" Hikvision',
                'intitle:"Network Camera" Hikvision login',
                'filetype:ini "Hikvision" "admin" "12345"',
                'inurl:"/ISAPI/Security/userCheck" Hikvision',
            ],
            "cves": ["CVE-2021-36260 (RCE crítico sem autenticação — afeta milhões de câmeras)"],
            "nota": "RTSP stream: rtsp://admin:12345@[IP]/Streaming/Channels/101",
        },

        "Hikvision — DS-7608NI / DS-7204HGHI NVR/DVR": {
            "creds": "user:admin  pass:12345  proto:HTTP",
            "risco": "CRÍTICO",
            "shodan": [
                'http.title:"DVR Login" port:8000',
                'http.title:"NVR Login" Hikvision',
                'product:"Hikvision DVR" port:8000',
                'port:8000 http.html:"Hikvision"',
                'port:37777 product:"Hikvision"',
                'http.html:"iVMS" port:80',
            ],
            "google": [
                'intitle:"DVR Login" Hikvision',
                'intitle:"NVR" Hikvision admin login',
                'inurl:"/doc/page/login.asp" NVR',
                'intitle:"Hikvision" DVR inurl:admin',
                'filetype:ini "Hikvision NVR" password',
            ],
            "cves": ["CVE-2021-36260"],
            "nota": "Porta 8000 (SDK), porta 80 (HTTP), porta 37777 (protocolo proprietário).",
        },

        "Dahua — IPC-HDW / SD PTZ": {
            "creds": "user:admin  pass:admin  proto:HTTP/RTSP",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Dahua" port:80',
                'http.title:"Dahua" port:80',
                'http.html:"IPC-HDW" port:80',
                'port:37777 product:"Dahua"',
                'port:554 product:"Dahua"',
                'product:"Dahua" has_screenshot:true',
                'product:"Dahua" country:AO,BR,MZ',
            ],
            "google": [
                'intitle:"Dahua" inurl:login',
                'intitle:"Dahua" camera admin login',
                'inurl:"/RPC2_Login" Dahua',
                'inurl:"/cgi-bin/magicBox.cgi" Dahua',
                'filetype:txt "admin" "admin" "Dahua"',
                '"rtsp://admin:admin@" Dahua camera',
            ],
            "cves": [],
            "nota": "Porta 37777 é protocolo proprietário Dahua. Muito usado em Angola e Moçambique.",
        },

        "Axis Communications — P3304 / M3004 / Q6035": {
            "creds": "user:root  pass:pass  proto:HTTP",
            "risco": "ALTO",
            "shodan": [
                'product:"Axis" port:80',
                'http.title:"AXIS" camera',
                'product:"Axis Network Camera"',
                'http.html:"AXIS" port:80,443',
                'product:"Axis" has_screenshot:true',
            ],
            "google": [
                'intitle:"Live View / - AXIS"',
                'intitle:"AXIS" camera inurl:login',
                'inurl:"/view/viewer_index.shtml" AXIS',
                'inurl:"/axis-cgi/jpg/image.cgi"',
                'filetype:conf "AXIS" camera "root" "pass"',
            ],
            "cves": [],
            "nota": "root/pass é credencial padrão histórica. Novas versões exigem setup.",
        },

        "Foscam — FI9821P / R2": {
            "creds": "user:admin  pass:(vazia)  proto:HTTP/RTSP",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"FOSCAM" port:88',
                'http.title:"Foscam" port:88',
                'http.html:"Foscam" port:80,88',
                'product:"Foscam" has_screenshot:true',
            ],
            "google": [
                'intitle:"Foscam" inurl:login',
                'intitle:"Foscam" camera admin',
                'inurl:":88/cgi-bin/CGIProxy.fcgi" Foscam',
                '"rtsp://admin:@" Foscam',
                'inurl:"/videostream.cgi" Foscam',
            ],
            "cves": [],
            "nota": "Porta 88 por padrão. Sem password! RTSP: rtsp://admin:@IP:554/videoMain",
        },
    },

    "IMPRESSORAS / MFP": {

        "HP — LaserJet Pro M402 / Color M553": {
            "creds": "user:admin  pass:(vazia)  proto:HTTP/SNMP",
            "risco": "MÉDIO",
            "shodan": [
                'product:"HP LaserJet" port:80',
                'http.title:"HP LaserJet" port:80',
                'http.html:"LaserJet Pro" port:80',
                'port:9100 banner:"HP LaserJet"',
                'product:"HP" printer port:80,443',
                'product:"HP LaserJet" country:AO,BR',
            ],
            "google": [
                'intitle:"HP LaserJet" inurl:admin',
                'intitle:"HP Embedded Web Server" printer',
                'inurl:"/hp/device/info" LaserJet',
                'inurl:"/hp/device/DeviceSummary.htm"',
                'filetype:htm "HP LaserJet" status',
                'intitle:"HP Color LaserJet" login',
            ],
            "cves": [],
            "nota": "Porta 9100 (JetDirect) sem auth. SNMP community 'public' permite leitura de config.",
        },

        "Xerox — WorkCentre 7845 / Phaser 3610": {
            "creds": "user:admin  pass:1111  proto:HTTP",
            "risco": "MÉDIO",
            "shodan": [
                'product:"Xerox WorkCentre" port:80',
                'http.title:"Xerox WorkCentre" login',
                'http.html:"Phaser 3610" port:80',
                'product:"Xerox" printer port:80',
                'http.html:"CentreWare" port:80',
            ],
            "google": [
                'intitle:"Xerox WorkCentre" login',
                'intitle:"Xerox" "CentreWare" admin',
                'inurl:"/webApp/wec/login" Xerox',
                'filetype:cfg "Xerox" "admin" "1111"',
                'intitle:"Xerox Phaser" admin login',
            ],
            "cves": [],
            "nota": "admin/1111. CentreWare Internet Services acessível sem SSL em muitos casos.",
        },

        "Canon — imageRUNNER ADVANCE": {
            "creds": "user:admin  pass:Canon1234  proto:HTTP",
            "risco": "MÉDIO",
            "shodan": [
                'product:"Canon imageRUNNER" port:80',
                'http.title:"imageRUNNER" login',
                'http.html:"Canon iRA" port:80',
                'product:"Canon" printer port:80,443',
            ],
            "google": [
                'intitle:"imageRUNNER ADVANCE" login',
                'intitle:"Canon" imageRUNNER admin',
                'inurl:"/portal/portal.html" Canon',
                'filetype:cfg "Canon iRA" "Canon1234"',
                'intitle:"Canon imageRUNNER" Remote UI',
            ],
            "cves": [],
            "nota": "Remote UI do imageRUNNER. Password Canon1234 é padrão documentado pela Canon.",
        },
    },

    "SCADA / ICS": {

        "Siemens — SIMATIC S7-300/S7-400 PLC": {
            "creds": "user:admin  pass:admin  proto:S7comm/HTTP",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Siemens S7" port:102',
                'port:102 product:"Siemens"',
                'port:102 country:AO,BR,PT',
                'banner:"S7-300" port:102',
                'product:"Siemens SIMATIC" port:80',
                'vuln:CVE-2019-13945 product:"Siemens"',
                'port:102 has_screenshot:true',
            ],
            "google": [
                'intitle:"Siemens" "SIMATIC S7" login',
                'intitle:"SIMATIC S7" PLC admin',
                'filetype:pdf "S7-300" "default password"',
                'filetype:xml "S7Project" "PlcSim"',
                'filetype:cfg "Siemens" "S7-300" password',
                'intitle:"TIA Portal" Siemens login',
            ],
            "cves": ["CVE-2019-13945"],
            "nota": "Protocolo S7comm porta 102. Sem autenticação nativa — acesso direto para ler/escrever PLCs.",
        },

        "Schneider — Modicon M340 / M580 PLC": {
            "creds": "user:USER  pass:USER  proto:HTTP/Modbus",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Schneider" port:502',
                'port:502 product:"Modicon"',
                'http.title:"Modicon" login',
                'product:"Schneider Electric" PLC',
                'port:502 country:AO,BR,PT,MZ',
                'banner:"BMXP342020" port:502',
            ],
            "google": [
                'intitle:"Modicon M340" login',
                'intitle:"Schneider" "Modicon" admin',
                'filetype:cfg "Modicon" "USER" "USER"',
                'intitle:"Unity Pro" Schneider login',
                'filetype:pdf "Modicon M340" password',
            ],
            "cves": [],
            "nota": "Modbus TCP porta 502. Sem autenticação — qualquer pessoa na rede pode ler/escrever PLCs.",
        },
    },

    "FIREWALLS / UTM": {

        "Fortinet — FortiGate 60E / 100D / 200E": {
            "creds": "user:admin  pass:(vazia)  proto:HTTPS/SSH",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Fortinet FortiGate" port:443',
                'http.title:"FortiGate" login',
                'ssl.cert.subject.cn:"FortiGate"',
                'http.html:"FortiOS" port:443',
                'product:"Fortinet" port:443 country:AO',
                'vuln:CVE-2018-13379 product:"Fortinet"',
                'vuln:CVE-2022-40684 product:"Fortinet"',
                'port:10443 product:"FortiGate"',
            ],
            "google": [
                'intitle:"FortiGate" inurl:login',
                'intitle:"FortiGate" "SSL VPN" login',
                'inurl:"/remote/login" FortiGate',
                'filetype:cfg "FortiGate" "config system admin"',
                'filetype:txt "FortiGate" "admin" password',
                'intitle:"Fortinet" SSL VPN login',
            ],
            "cves": ["CVE-2018-13379 (path traversal — exfiltrou 50000+ credenciais)", "CVE-2022-40684 (bypass de autenticação)"],
            "nota": "CVE-2018-13379: path traversal exfiltrou credenciais de 50000+ FortiGates.",
        },

        "Palo Alto — PA-220 / PA-820 / PA-3220": {
            "creds": "user:admin  pass:admin  proto:HTTPS/SSH",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Palo Alto" port:443',
                'http.title:"GlobalProtect" login',
                'ssl.cert.issuer.cn:"Palo Alto"',
                'http.html:"PAN-OS" port:443',
                'vuln:CVE-2020-2021 product:"Palo Alto"',
            ],
            "google": [
                'intitle:"Palo Alto" "GlobalProtect" login',
                'intitle:"PAN-OS" admin login',
                'inurl:"/global-protect/login" Palo Alto',
                'filetype:xml "panos" "admin" password',
                'filetype:cfg "Palo Alto" "admin" "admin"',
            ],
            "cves": ["CVE-2020-2021 (bypass de autenticação crítico no GlobalProtect)"],
            "nota": "CVE-2020-2021: amplamente explorado. admin/admin é padrão na interface de gestão.",
        },

        "SonicWall — TZ400 / NSA 2650": {
            "creds": "user:admin  pass:password  proto:HTTPS",
            "risco": "ALTO",
            "shodan": [
                'product:"SonicWall" port:443',
                'http.title:"SonicWall" login',
                'ssl.cert.subject.cn:"SonicWall"',
                'http.html:"SonicOS" port:443',
                'vuln:CVE-2021-20016 product:"SonicWall"',
            ],
            "google": [
                'intitle:"SonicWall" inurl:main.html',
                'intitle:"SonicWall" NSA login',
                'inurl:"/auth.html" SonicWall',
                'filetype:cfg "SonicWall" "admin" "password"',
            ],
            "cves": ["CVE-2021-20016 (SQL injection crítico no SonicWall SMA)"],
            "nota": "admin/password é credencial padrão.",
        },
    },

    "NAS / STORAGE / BACKUP": {

        "Synology — DS220+ / DS918+ / DS1520+": {
            "creds": "user:admin  pass:admin  proto:HTTP/SSH",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Synology DiskStation" port:5000',
                'http.title:"Synology" port:5000',
                'http.html:"DiskStation" port:5000',
                'port:5000 product:"Synology"',
                'port:5001 product:"Synology"',
                'vuln:CVE-2021-31439 product:"Synology"',
                'product:"Synology" country:AO,BR,PT',
            ],
            "google": [
                'intitle:"Synology DiskStation" login',
                'inurl:":5000/webman/login.cgi"',
                'intitle:"Synology" inurl:login',
                'inurl:"/webman/index.cgi" Synology',
                'filetype:yml "synology" "admin" password',
                'site:*.synology.me login',
            ],
            "cves": ["CVE-2021-31439"],
            "nota": "Alvo frequente de ransomware (eCh0raix). Backups expostos na internet.",
        },

        "QNAP — TS-453Be / TVS-473e": {
            "creds": "user:admin  pass:admin  proto:HTTP/SSH",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"QNAP" port:8080',
                'http.title:"QNAP" port:8080',
                'http.html:"QNAP NAS" port:80',
                'port:8080 product:"QNAP"',
                'vuln:CVE-2021-28799 product:"QNAP"',
                'vuln:CVE-2022-27596 product:"QNAP"',
            ],
            "google": [
                'intitle:"QNAP" inurl:login.html',
                'inurl:":8080/cgi-bin/login" QNAP',
                'intitle:"QNAP NAS" admin login',
                'filetype:yml "QNAP" "admin" backup',
                'site:*.myqnapcloud.com login',
            ],
            "cves": ["CVE-2021-28799 (ransomware QLocker)", "CVE-2022-27596"],
            "nota": "Ransomware QLocker explorou QNAP sem autenticação. admin/admin é padrão.",
        },
    },

    "BASES DE DADOS": {

        "MongoDB (sem autenticação)": {
            "creds": "user:admin  pass:(sem auth)  proto:TCP 27017",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"MongoDB" port:27017',
                'port:27017 product:"MongoDB" -authentication',
                'port:27017 country:AO,BR,PT',
                'port:27017 country:AO',
                'port:27017 has_screenshot:true',
            ],
            "google": [
                'intitle:"Mongo Express" inurl:login',
                'inurl:":27017" MongoDB exposed',
                'filetype:env "MONGO_URI" password',
                'filetype:py password "mongoose.connect"',
                '"MONGODB_URL" filetype:env admin',
                'filetype:js "mongoose.connect" password',
            ],
            "cves": [],
            "nota": "MongoDB sem autenticação expõe TODOS os dados. Angola tem instâncias expostas. Porta 27017.",
        },

        "Redis (sem autenticação)": {
            "creds": "user:(sem user)  pass:(sem auth)  proto:TCP 6379",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Redis" port:6379',
                'port:6379 -authentication',
                'port:6379 country:AO,BR,PT',
                'port:6379 has_screenshot:true',
                'banner:"redis_version" port:6379',
            ],
            "google": [
                '"redis://" filetype:env',
                '"REDIS_URL" filetype:env password',
                'filetype:conf "requirepass" redis',
                'filetype:yml "redis" "host" "port: 6379"',
                '"redis.conf" filetype:conf requirepass',
            ],
            "cves": [],
            "nota": "Redis sem requirepass é acessível por qualquer um. Usado em cache e sessões.",
        },

        "Elasticsearch (sem autenticação)": {
            "creds": "user:elastic  pass:changeme  proto:HTTP 9200",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Elasticsearch" port:9200',
                'port:9200 product:"Elasticsearch" -auth',
                'port:9200 country:AO,BR,PT',
                'http.title:"Elasticsearch" port:9200',
                'port:9200 has_screenshot:true',
            ],
            "google": [
                'intitle:"Elasticsearch" inurl:9200',
                'inurl:":9200/_cat/indices" elastic',
                'filetype:yml password "elasticsearch"',
                '"xpack.security.enabled: false" filetype:yml',
                'filetype:env "ELASTICSEARCH_URL"',
            ],
            "cves": [],
            "nota": "Elasticsearch sem X-Pack Security expõe todos os índices. Responsável por vazamentos massivos.",
        },

        "MySQL / MariaDB (root sem password)": {
            "creds": "user:root  pass:(vazia)  proto:TCP 3306",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"MySQL" port:3306',
                'port:3306 product:"MySQL"',
                'port:3306 country:AO,BR,PT',
                'banner:"mysql_native_password" port:3306',
            ],
            "google": [
                'intitle:"phpMyAdmin" "Welcome to phpMyAdmin"',
                'intitle:"phpMyAdmin" inurl:index.php',
                'filetype:sql "INSERT INTO" "users" "password"',
                'filetype:env "DB_PASSWORD=" "DB_USER=root"',
                '"mysql_connect" filetype:php password',
                'filetype:sql "CREATE TABLE users"',
            ],
            "cves": [],
            "nota": "MySQL/MariaDB com root sem password. phpMyAdmin exposto permite acesso total via browser.",
        },

        "Microsoft SQL Server (sa sem password)": {
            "creds": "user:sa  pass:(vazia)  proto:TCP 1433",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Microsoft SQL Server" port:1433',
                'port:1433 product:"Microsoft SQL"',
                'port:1433 country:AO,BR,PT',
                'banner:"Microsoft SQL Server" port:1433',
            ],
            "google": [
                'intitle:"SQL Server" login admin',
                'filetype:udl "Provider=SQLOLEDB" password',
                'filetype:config "connectionString" "Integrated Security"',
                'filetype:xml "Data Source=" "Initial Catalog=" password',
                '"sa" "" filetype:config connectionstring',
            ],
            "cves": [],
            "nota": "SQL Server com autenticação mista e sa sem password permite execução de xp_cmdshell (RCE).",
        },
    },

    "TELECOMUNICAÇÕES / VoIP": {

        "Grandstream — UCM6208 / UCM6510 IPBX": {
            "creds": "user:admin  pass:admin  proto:HTTP",
            "risco": "ALTO",
            "shodan": [
                'http.title:"UCM6208" port:80',
                'product:"Grandstream" port:80',
                'http.html:"UCM6" port:80',
                'http.title:"Grandstream" login',
                'port:5060 product:"Grandstream"',
            ],
            "google": [
                'intitle:"Grandstream UCM" login',
                'intitle:"UCM6208" admin login',
                'inurl:"/cgi-bin/api.values.get" Grandstream',
                'filetype:cfg "Grandstream" "admin" SIP',
                'intitle:"Grandstream" inurl:admin',
            ],
            "cves": [],
            "nota": "admin/admin. Acesso permite escutar chamadas e fazer toll fraud internacional.",
        },

        "ZTE — C320 / C300 OLT": {
            "creds": "user:admin  pass:admin  proto:Telnet/HTTP",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"ZTE OLT" port:23',
                'banner:"ZTE C320" port:23',
                'http.html:"C320" port:80',
                'product:"ZTE" port:23 country:AO',
                'banner:"ZTE Corporation"',
            ],
            "google": [
                'intitle:"ZTE C320" OLT login',
                'intitle:"ZTE OLT" admin',
                'filetype:cfg "ZTE C320" "admin" OLT',
                'site:.ao intitle:"ZTE" OLT',
                'intitle:"GPON OLT" ZTE login',
            ],
            "cves": [],
            "nota": "OLTs ZTE controlam redes GPON inteiras. Telnet sem criptografia expõe credenciais.",
        },

        "ZTE — F601 / F609 GPON ONT": {
            "creds": "user:admin  pass:admin  proto:HTTP/Telnet",
            "risco": "ALTO",
            "shodan": [
                'http.title:"ZTE F601" port:80',
                'product:"ZTE F601"',
                'http.html:"ZTE" "F609" port:80',
                'product:"ZTE" ONT port:80 country:AO',
            ],
            "google": [
                'intitle:"ZTE F601" admin login',
                'intitle:"ZTE F609" login',
                'inurl:"/getpage.gch" ZTE ONT',
                'filetype:cfg "ZTE F601" password',
                'site:.ao intitle:"ZTE" ONT login',
            ],
            "cves": [],
            "nota": "ONTs ZTE amplamente usados em Angola/Moçambique pela UNITEL, Movicel e outras operadoras.",
        },
    },

    "SERVIDORES / PAINÉIS DE GESTÃO": {

        "VMware ESXi 7.0 / 8.0": {
            "creds": "user:root  pass:(vazia)  proto:SSH/HTTPS",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"VMware ESXi" port:443',
                'http.title:"ESXi" port:443',
                'ssl.cert.subject.cn:"VMware"',
                'port:443 http.html:"VMware ESXi"',
                'vuln:CVE-2021-21985 product:"VMware"',
                'vuln:CVE-2021-22005 product:"VMware"',
                'port:902 product:"VMware"',
            ],
            "google": [
                'intitle:"VMware ESXi" login',
                'intitle:"VMware" ESXi inurl:login',
                'inurl:"/ui/" VMware ESXi login',
                'filetype:vmx "VMware" password',
                'filetype:ovf "VMware" password',
                'intitle:"VMware vCenter" login',
            ],
            "cves": ["CVE-2021-21985 (RCE vCenter)", "CVE-2021-22005 (RCE vCenter)"],
            "nota": "root sem password em ESXi de instalação rápida. CVEs críticos no vCenter.",
        },

        "Proxmox VE 7.x / 8.x": {
            "creds": "user:root  pass:(vazia)  proto:SSH/HTTPS",
            "risco": "ALTO",
            "shodan": [
                'product:"Proxmox VE" port:8006',
                'http.title:"Proxmox" port:8006',
                'http.html:"Proxmox Virtual" port:8006',
                'port:8006 product:"Proxmox"',
                'port:8006 country:AO,BR,PT',
            ],
            "google": [
                'intitle:"Proxmox VE" login',
                'inurl:":8006" Proxmox login',
                'inurl:"/#v1:0:18:4" Proxmox',
                'filetype:cfg "Proxmox" "root" password',
                'site:.ao intitle:"Proxmox" login',
            ],
            "cves": [],
            "nota": "Proxmox VE: hypervisor open-source. root@pam sem password em instalações rápidas. Porta 8006.",
        },

        "Grafana Dashboard": {
            "creds": "user:admin  pass:admin  proto:HTTP 3000",
            "risco": "ALTO",
            "shodan": [
                'product:"Grafana" port:3000',
                'http.title:"Grafana" port:3000',
                'port:3000 http.html:"Grafana"',
                'product:"Grafana" country:AO,BR',
            ],
            "google": [
                'intitle:"Grafana" inurl:login',
                'inurl:":3000/login" Grafana',
                'intitle:"Grafana" admin dashboard',
                'filetype:yml "grafana" "admin_password"',
                '"GF_SECURITY_ADMIN_PASSWORD" filetype:env',
            ],
            "cves": [],
            "nota": "Grafana admin/admin por padrão. Expõe métricas, alertas e ligações a BDs sensíveis.",
        },

        "Jenkins CI/CD": {
            "creds": "user:admin  pass:admin  proto:HTTP 8080",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Jenkins" port:8080',
                'http.title:"Jenkins" port:8080',
                'http.html:"Jenkins" port:8080',
                'port:8080 product:"Jenkins"',
                'vuln:CVE-2019-1003000 product:"Jenkins"',
            ],
            "google": [
                'intitle:"Jenkins" "Manage Jenkins"',
                'intitle:"Jenkins" inurl:login',
                'inurl:":8080/jenkins" admin',
                'filetype:xml "hudson.util.Secret" Jenkins',
                'filetype:groovy "withCredentials" jenkins',
                '"jenkins_home" filetype:xml password',
            ],
            "cves": ["CVE-2019-1003000 (Jenkins RCE via Groovy Script)"],
            "nota": "Jenkins sem auth: execução de Groovy Script = RCE total. admin/admin é padrão comum.",
        },

        "Dell iDRAC 9 (BMC)": {
            "creds": "user:root  pass:calvin  proto:HTTPS",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"Dell iDRAC" port:443',
                'http.title:"iDRAC" port:443',
                'ssl.cert.subject.cn:"idrac"',
                'http.html:"iDRAC9" port:443',
                'port:443 http.title:"iDRAC"',
            ],
            "google": [
                'intitle:"iDRAC" "Dell" login',
                'intitle:"Dell iDRAC9" login',
                'inurl:"/login.html" iDRAC',
                'filetype:cfg "idrac" "root" "calvin"',
            ],
            "cves": [],
            "nota": "root/calvin é a credencial padrão. Acesso total ao servidor — ligar, desligar, instalar OS.",
        },

        "Supermicro IPMI BMC": {
            "creds": "user:ADMIN  pass:ADMIN  proto:HTTP/IPMI",
            "risco": "CRÍTICO",
            "shodan": [
                'port:623 product:"IPMI"',
                'product:"Supermicro IPMI" port:443',
                'http.title:"IPMI" Supermicro',
                'port:623 country:AO,BR,PT',
                'vuln:CVE-2013-4786 port:623',
            ],
            "google": [
                'intitle:"Supermicro IPMI" login',
                'intitle:"IPMI" Supermicro admin',
                'inurl:"/cgi/login.cgi" IPMI',
                'filetype:cfg "IPMI" "ADMIN" "ADMIN"',
            ],
            "cves": ["CVE-2013-4786 (IPMI Cipher 0 — bypass total de autenticação)"],
            "nota": "ADMIN/ADMIN é padrão. CVE-2013-4786: Cipher 0 permite bypass total.",
        },
    },

    "IoT / ACCESS POINTS / CONTROLO DE ACESSO": {

        "Ubiquiti — UniFi AP AC Pro / AC Lite": {
            "creds": "user:ubnt  pass:ubnt  proto:SSH",
            "risco": "ALTO",
            "shodan": [
                'product:"Ubiquiti" port:22',
                'http.title:"UniFi" login',
                'port:8443 http.title:"UniFi"',
                'product:"Ubiquiti" port:10001',
                'port:10001 product:"Ubiquiti"',
                'vuln:CVE-2021-22909 product:"Ubiquiti"',
                'product:"Ubiquiti" country:AO,BR,MZ',
            ],
            "google": [
                'intitle:"UniFi Network" login',
                'intitle:"Ubiquiti" inurl:login',
                'inurl:":8443/manage" UniFi',
                'filetype:cfg "ubnt" "ubnt" Ubiquiti',
                'site:.ao intitle:"UniFi" login',
            ],
            "cves": ["CVE-2021-22909"],
            "nota": "ubnt/ubnt em SSH. Port 10001/UDP revela todos os APs na rede.",
        },

        "ZKTeco — inFace 602 / F18 Fingerprint": {
            "creds": "user:admin  pass:admin123  proto:HTTP",
            "risco": "CRÍTICO",
            "shodan": [
                'product:"ZKTeco" port:80',
                'http.title:"ZKTeco" login',
                'port:4370 product:"ZKTeco"',
                'http.html:"ZKBioSecurity" port:80',
                'vuln:CVE-2019-12276 product:"ZKTeco"',
                'product:"ZKTeco" country:AO,BR,MZ',
            ],
            "google": [
                'intitle:"ZKTeco" inurl:login',
                'intitle:"ZKBioSecurity" login',
                'inurl:"/zkbiosecurity" login',
                'filetype:mdb "ZKTeco" "card" "PIN"',
                'filetype:csv "ZKTeco" "user" "fingerprint"',
                'site:.ao intitle:"ZKTeco" login',
            ],
            "cves": ["CVE-2019-12276 (SQL injection não autenticado)"],
            "nota": "CVE-2019-12276: SQL injection não autenticado. Muito usado em Angola para ponto de acesso.",
        },

        "Shelly 1 / Shelly Pro (IoT Relay)": {
            "creds": "user:admin  pass:(vazia)  proto:HTTP",
            "risco": "MÉDIO",
            "shodan": [
                'product:"Shelly" port:80',
                'http.title:"Shelly" login',
                'http.html:"Shelly" port:80',
                'port:1883 product:"MQTT" shelly',
            ],
            "google": [
                'intitle:"Shelly" smart home login',
                'inurl:"/settings" Shelly',
                'filetype:json "shelly" "wifi" password',
                '"Shelly" "MQTT" "broker" filetype:conf',
            ],
            "cves": [],
            "nota": "Shelly sem password por padrão. MQTT sem TLS expõe todos os estados dos relês em tempo real.",
        },
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# GUIA DE DEFESA
# ─────────────────────────────────────────────────────────────────────────────

DEFESA = {
    "IMEDIATO — Configurações Essenciais": [
        "Nunca exponha painéis de admin diretamente na internet",
        "Use HTTPS em TODAS as páginas de login — credenciais em HTTP são intercetáveis",
        "Altere IMEDIATAMENTE todas as credenciais padrão após instalação",
        "Bloqueie o acesso a /admin, /wp-admin, /administrator por IP ou VPN",
        "Desative contas padrão não utilizadas (admin, guest, operator, test)",
        "Configure robots.txt para não indexar páginas de login e admin",
    ],
    "CURTO PRAZO — Autenticação Segura": [
        "Implemente MFA em TODOS os sistemas críticos",
        "Configure lockout: bloquear após 5 tentativas falhadas por 15 minutos",
        "Rate limiting: máximo 10 tentativas de login por minuto por IP",
        "Use CAPTCHA em formulários de login públicos",
        "Instala fail2ban para bloquear automaticamente IPs suspeitos",
        "Configure alertas de login suspeito: localização nova, hora inusual, IP desconhecido",
    ],
    "MÉDIO PRAZO — Monitorização e Auditoria": [
        "Use Shodan Monitor para alertas quando novos serviços aparecem indexados",
        "Audite regularmente com os dorks deste manual",
        "Implemente WAF (Web Application Firewall)",
        "Configure SIEM para detetar padrões de brute force e credential stuffing",
        "Password policy: mínimo 12 caracteres, sem passwords comuns, rotação periódica",
        "Use gestor de passwords corporativo: Bitwarden, 1Password Teams, HashiCorp Vault",
    ],
    "LONGO PRAZO — Zero Trust e Maturidade": [
        "Adote arquitetura Zero Trust: verificação contínua de identidade",
        "Implemente SSO (Single Sign-On) com IdP seguro: Keycloak, Okta, Azure AD",
        "Use PAM (Privileged Access Management): CyberArk, BeyondTrust",
        "Realize pentests anuais focados em autenticação",
        "Forme a equipa sobre phishing, engenharia social e boas práticas de passwords",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# UTILITÁRIOS DE IMPRESSÃO
# ─────────────────────────────────────────────────────────────────────────────

def cabecalho():
    print()
    print(cor(LINHA_LARGA, C.CYAN))
    print(cor("  SHODAN + GOOGLE DORKS — AUDITORIA DEFENSIVA COMPLETA", C.BOLD + C.CYAN))
    print(cor("  Login Pages · Fabricantes · Modelos · Credenciais Padrão", C.CYAN))
    print(cor(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", C.DIM))
    print(cor(LINHA_LARGA, C.CYAN))
    print()

def titulo_secao(texto: str, num: int = 0):
    print()
    print(cor(LINHA_MEDIA, C.BLUE))
    pref = f"[{num:02d}] " if num else "    "
    print(cor(f"{pref}{texto}", C.BOLD + C.BLUE))
    print(cor(LINHA_MEDIA, C.BLUE))

def subtitulo(texto: str):
    print(cor(f"\n  ▸ {texto}", C.MAGENTA))

def ok(msg: str):
    print(cor(f"    ✔  {msg}", C.GREEN))

def aviso(msg: str):
    print(cor(f"    ⚠  {msg}", C.YELLOW))

def erro(msg: str):
    print(cor(f"    ✖  {msg}", C.RED))

def info(msg: str):
    print(cor(f"    ℹ  {msg}", C.CYAN))

def dork_linha(tipo: str, query: str):
    if tipo == "SHODAN":
        c = C.RED
    else:
        c = C.BLUE
    t = cor(f"[{tipo:6s}]", c)
    print(f"      {t}  {query}")

def badge_risco(risco: str) -> str:
    cores = {
        "CRÍTICO": C.RED + C.BOLD,
        "ALTO"   : C.RED,
        "MÉDIO"  : C.YELLOW,
        "BAIXO"  : C.GREEN,
    }
    c = cores.get(risco, C.WHITE)
    return cor(f"[{risco}]", c)

def nota_caixa(texto: str, tipo: str = "INFO"):
    cor_map = {"NOTA": C.CYAN, "AVISO": C.YELLOW, "CRÍTICO": C.RED}
    c = cor_map.get(tipo, C.CYAN)
    print()
    print(cor(f"  ┌─ {tipo} {'─' * (70 - len(tipo))}", c))
    for linha in texto.split("\n"):
        print(cor(f"  │  {linha}", c))
    print(cor(f"  └─{'─' * 73}", c))

def gerar_url_shodan(query: str, pais: str = "") -> str:
    q = query
    if pais:
        q += f" country:{pais}"
    return f"https://www.shodan.io/search?query={urllib.parse.quote(q)}"

def gerar_url_google(query: str) -> str:
    return f"https://www.google.com/search?q={urllib.parse.quote(query)}"

# ─────────────────────────────────────────────────────────────────────────────
# MÓDULOS DE APRESENTAÇÃO
# ─────────────────────────────────────────────────────────────────────────────

def listar_login_dorks(filtro_risco: str = ""):
    titulo_secao("DORKS DE LOGIN — 20 CATEGORIAS (800+ DORKS)", 1)
    info("Dorks Shodan (vermelho) e Google (azul) para páginas de login.\n")

    for idx, (cat, dados) in enumerate(LOGIN_DORKS.items(), start=1):
        risco = dados.get("risco", "?")
        if filtro_risco and risco != filtro_risco:
            continue

        print()
        print(cor(f"  ┌{'─' * 74}┐", C.DIM))
        print(f"  │  {cor(cat, C.BOLD + C.WHITE):<70}  {badge_risco(risco)}  │")
        print(f"  │  {cor(dados.get('descricao', ''), C.DIM):<72}│")
        print(cor(f"  └{'─' * 74}┘", C.DIM))

        subtitulo("SHODAN")
        for q in dados["shodan"]:
            dork_linha("SHODAN", q)

        subtitulo("GOOGLE")
        for q in dados["google"]:
            dork_linha("GOOGLE", q)

        if dados.get("credenciais"):
            subtitulo("CREDENCIAIS PADRÃO")
            for c2 in dados["credenciais"]:
                aviso(c2)

        if dados.get("cves"):
            subtitulo("CVEs CRÍTICOS")
            for cve in dados["cves"]:
                erro(cve)

        nota_caixa(dados.get("nota", ""), "NOTA")

def listar_fabricantes_dorks(categoria_filtro: str = ""):
    titulo_secao("DORKS POR FABRICANTE E MODELO (600+ DORKS)", 2)
    info("Dorks específicos por fabricante/modelo com credenciais padrão e CVEs.\n")

    for cat, fabricantes in FABRICANTES_DORKS.items():
        if categoria_filtro and categoria_filtro.upper() not in cat.upper():
            continue

        titulo_secao(f"CATEGORIA: {cat}")

        for modelo, dados in fabricantes.items():
            risco = dados.get("risco", "?")
            print()
            print(cor(f"  ═══ {modelo} {badge_risco(risco)} {'═' * max(1, 60 - len(modelo))}", C.BOLD + C.MAGENTA))
            print(cor(f"  Credenciais: {dados.get('creds', 'N/A')}", C.ORANGE))

            subtitulo("SHODAN")
            for q in dados["shodan"]:
                dork_linha("SHODAN", q)

            subtitulo("GOOGLE")
            for q in dados["google"]:
                dork_linha("GOOGLE", q)

            if dados.get("cves"):
                subtitulo("CVEs")
                for cve in dados["cves"]:
                    erro(cve)

            nota_caixa(dados.get("nota", ""), "NOTA")

def pesquisa_rapida(termo: str):
    titulo_secao(f"PESQUISA RÁPIDA: '{termo}'")
    info(f"A procurar dorks relacionados com '{termo}'...\n")

    encontrou = False
    termo_l = termo.lower()

    # Login dorks
    for cat, dados in LOGIN_DORKS.items():
        matches = [q for q in dados["shodan"] + dados["google"]
                   if termo_l in q.lower()]
        if matches or termo_l in cat.lower():
            print(cor(f"\n  📂 {cat} {badge_risco(dados.get('risco','?'))}", C.BOLD + C.WHITE))
            for q in matches[:5]:
                tipo = "SHODAN" if q in dados["shodan"] else "GOOGLE"
                dork_linha(tipo, q)
            encontrou = True

    # Fabricantes dorks
    for cat, fabricantes in FABRICANTES_DORKS.items():
        for modelo, dados in fabricantes.items():
            if termo_l in modelo.lower() or termo_l in cat.lower():
                matches_s = [q for q in dados["shodan"] if termo_l in q.lower()]
                matches_g = [q for q in dados["google"] if termo_l in q.lower()]
                all_m = dados["shodan"][:3] + dados["google"][:3]
                print(cor(f"\n  🔧 {modelo} {badge_risco(dados.get('risco','?'))}", C.BOLD + C.MAGENTA))
                print(cor(f"     Credenciais: {dados.get('creds','')}", C.ORANGE))
                for q in all_m:
                    tipo = "SHODAN" if q in dados["shodan"] else "GOOGLE"
                    dork_linha(tipo, q)
                encontrou = True

    if not encontrou:
        aviso(f"Nenhum dork encontrado para '{termo}'.")
        info("Experimenta: hikvision, cisco, wordpress, mysql, vpn, scada, etc.")

def exportar_json(caminho: str = "/tmp/dorks_completo.json"):
    data = {
        "gerado_em"         : datetime.datetime.now().isoformat(),
        "total_login_cats"  : len(LOGIN_DORKS),
        "total_fab_cats"    : len(FABRICANTES_DORKS),
        "login_dorks"       : LOGIN_DORKS,
        "fabricantes_dorks" : FABRICANTES_DORKS,
        "guia_defesa"       : DEFESA,
    }
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    ok(f"Exportado para: {caminho}")
    return caminho

def exportar_texto(caminho: str = "/tmp/dorks_completo.txt"):
    linhas = []
    linhas.append("=" * 80)
    linhas.append("SHODAN + GOOGLE DORKS — AUDITORIA DEFENSIVA COMPLETA")
    linhas.append(f"Gerado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    linhas.append("=" * 80)
    linhas.append("")

    linhas.append("## DORKS DE LOGIN — 20 CATEGORIAS")
    linhas.append("")
    for cat, dados in LOGIN_DORKS.items():
        linhas.append(f"### {cat} [{dados.get('risco','')}]")
        linhas.append(f"Descrição: {dados.get('descricao','')}")
        linhas.append("--- SHODAN ---")
        for q in dados["shodan"]:
            linhas.append(f"  {q}")
        linhas.append("--- GOOGLE ---")
        for q in dados["google"]:
            linhas.append(f"  {q}")
        if dados.get("credenciais"):
            linhas.append("--- CREDENCIAIS PADRÃO ---")
            for c2 in dados["credenciais"]:
                linhas.append(f"  {c2}")
        if dados.get("cves"):
            linhas.append("--- CVEs ---")
            for cve in dados["cves"]:
                linhas.append(f"  {cve}")
        linhas.append(f"NOTA: {dados.get('nota','')}")
        linhas.append("")

    linhas.append("## DORKS POR FABRICANTE E MODELO")
    linhas.append("")
    for cat, fabricantes in FABRICANTES_DORKS.items():
        linhas.append(f"### CATEGORIA: {cat}")
        for modelo, dados in fabricantes.items():
            linhas.append(f"#### {modelo} [{dados.get('risco','')}]")
            linhas.append(f"Credenciais: {dados.get('creds','')}")
            linhas.append("--- SHODAN ---")
            for q in dados["shodan"]:
                linhas.append(f"  {q}")
            linhas.append("--- GOOGLE ---")
            for q in dados["google"]:
                linhas.append(f"  {q}")
            if dados.get("cves"):
                linhas.append("--- CVEs ---")
                for cve in dados["cves"]:
                    linhas.append(f"  {cve}")
            linhas.append(f"NOTA: {dados.get('nota','')}")
            linhas.append("")

    linhas.append("## GUIA DE DEFESA")
    for fase, medidas in DEFESA.items():
        linhas.append(f"### {fase}")
        for m in medidas:
            linhas.append(f"  → {m}")
        linhas.append("")

    with open(caminho, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas))
    ok(f"Exportado para: {caminho}")
    return caminho

def mostrar_estatisticas():
    titulo_secao("ESTATÍSTICAS DA BASE DE DADOS DE DORKS")

    total_login_shodan = sum(len(d["shodan"]) for d in LOGIN_DORKS.values())
    total_login_google = sum(len(d["google"]) for d in LOGIN_DORKS.values())
    total_fab_shodan   = sum(len(m["shodan"]) for fab in FABRICANTES_DORKS.values() for m in fab.values())
    total_fab_google   = sum(len(m["google"]) for fab in FABRICANTES_DORKS.values() for m in fab.values())
    total_modelos      = sum(len(fab) for fab in FABRICANTES_DORKS.values())
    total_cves         = sum(len(d.get("cves",[])) for d in LOGIN_DORKS.values()) + \
                         sum(len(m.get("cves",[])) for fab in FABRICANTES_DORKS.values() for m in fab.values())

    criticos = sum(1 for d in LOGIN_DORKS.values() if d.get("risco") == "CRÍTICO")
    criticos += sum(1 for fab in FABRICANTES_DORKS.values() for m in fab.values() if m.get("risco") == "CRÍTICO")

    print()
    ok(f"Total Dorks Login   Shodan : {total_login_shodan}")
    ok(f"Total Dorks Login   Google : {total_login_google}")
    ok(f"Total Dorks Fabric. Shodan : {total_fab_shodan}")
    ok(f"Total Dorks Fabric. Google : {total_fab_google}")
    info(f"TOTAL GERAL                : {total_login_shodan + total_login_google + total_fab_shodan + total_fab_google}")
    print()
    ok(f"Categorias Login           : {len(LOGIN_DORKS)}")
    ok(f"Categorias Fabricante      : {len(FABRICANTES_DORKS)}")
    ok(f"Modelos/Produtos           : {total_modelos}")
    ok(f"CVEs documentados          : {total_cves}")
    erro(f"Entradas com risco CRÍTICO : {criticos}")

def mostrar_defesa():
    titulo_secao("GUIA COMPLETO DE DEFESA — PROTEÇÃO DE LOGIN PAGES")
    for fase, medidas in DEFESA.items():
        subtitulo(fase)
        for m in medidas:
            print(f"    {cor('→', C.GREEN)}  {m}")

def mostrar_glossario():
    titulo_secao("GLOSSÁRIO TÉCNICO")

    termos = {
        "Authentication Bypass": "Vulnerabilidade que permite contornar autenticação sem credenciais válidas.",
        "Banner": "Mensagem de identificação enviada por um serviço de rede ao estabelecer conexão. O Shodan usa banners para indexar dispositivos.",
        "BMC": "Baseboard Management Controller. Chip de gestão independente em servidores (Dell iDRAC, HP iLO, IPMI).",
        "Brute Force": "Ataque que testa sistematicamente listas de credenciais. Ferramenta: Hydra.",
        "Credential Stuffing": "Ataque que usa credenciais vazadas de outras brechas. Mitigado com MFA.",
        "CVE": "Common Vulnerabilities and Exposures. Identificador padrão de vulnerabilidades. Shodan Premium: vuln:CVE-XXXX.",
        "Default Credential": "Utilizador e password pré-definidos pelo fabricante. Ex: admin/admin, admin/(vazia).",
        "DICOM": "Digital Imaging and Communications in Medicine. Protocolo médico (porta 104). Frequentemente sem autenticação.",
        "Dork": "Pesquisa avançada usando operadores especiais no Shodan ou Google.",
        "Favicon Hash": "Hash MD5 do ícone favicon.ico. Shodan: http.favicon.hash:-247388890.",
        "GHDB": "Google Hacking Database em exploit-db.com. +7000 Google Dorks categorizados.",
        "has_screenshot": "Filtro Shodan para dispositivos com screenshot capturado. Poderoso para câmeras.",
        "http.title": "Filtro Shodan que pesquisa no título HTML. Ex: http.title:\"DVR Login\".",
        "iDRAC": "Integrated Dell Remote Access Controller. root/calvin é o padrão. Acesso total ao servidor.",
        "iLO": "HP Integrated Lights-Out. Gestão remota de servidores HP. Porta 443.",
        "intitle": "Operador Google que pesquisa no título HTML. Ex: intitle:\"Admin Login\".",
        "inurl": "Operador Google que pesquisa na URL. Ex: inurl:/admin/login.",
        "IPMI": "Intelligent Platform Management Interface. Porta UDP 623. CVE-2013-4786: bypass total.",
        "JetDirect": "Protocolo de impressão HP porta 9100 sem autenticação. Permite capturar documentos.",
        "MFA": "Multi-Factor Authentication. A mitigação mais eficaz contra credential stuffing e brute force.",
        "Modbus TCP": "Protocolo industrial sem autenticação, porta 502. Criado em 1979.",
        "MQTT": "Protocolo IoT. Porta 1883 sem TLS. Brokers sem autenticação expõem todos os tópicos.",
        "OLT": "Optical Line Terminal. Controla centenas/milhares de clientes GPON.",
        "ONT": "Optical Network Terminal. Terminal instalado no cliente. Ex: Huawei HG8247H.",
        "OSINT": "Open Source Intelligence. Recolha de informação de fontes públicas.",
        "Password Spraying": "Testa UMA password comum contra MUITOS utilizadores. Evita lockouts.",
        "RCE": "Remote Code Execution. Execução de código arbitrário num sistema remoto.",
        "RTSP": "Real Time Streaming Protocol. Porta 554. Ex: rtsp://admin:12345@[IP]/stream1.",
        "S7comm": "Protocolo Siemens para PLCs S7. Porta TCP 102. Sem autenticação nativa.",
        "Shodan": "Motor de busca para dispositivos conectados à internet. shodan.io",
        "site:": "Operador Google para restringir ao domínio. Ex: site:gov.ao",
        "SQL Injection Login": "Injeção SQL no formulário de login: admin'-- ou ' OR '1'='1.",
        "TR-069/CWMP": "Protocolo de gestão remota de CPE. Porta 7547. CVE-2014-9222 permite RCE.",
        "Winbox": "Protocolo proprietário MikroTik. Porta 8291. Admin sem password é padrão.",
        "Zero Trust": "Arquitetura de segurança com verificação contínua de identidade sem confiança implícita.",
    }

    for termo, definicao in sorted(termos.items()):
        print(f"\n  {cor(termo, C.BOLD + C.CYAN)}")
        print(f"     {definicao}")

def mostrar_credenciais_padrao():
    titulo_secao("TABELA DE CREDENCIAIS PADRÃO — TODOS OS FABRICANTES")
    info("Credenciais padrão de fábrica por fabricante e modelo.\n")

    h1 = cor("MODELO/PRODUTO", C.BOLD)
    h2 = cor("UTILIZADOR", C.BOLD)
    h3 = cor("PASSWORD", C.BOLD)
    h4 = cor("PROTOCOLO", C.BOLD)
    print(f"  {h1:<55}{h2:<25}{h3:<30}{h4}")
    print(cor("  " + "─" * 95, C.DIM))

    for cat, fabricantes in FABRICANTES_DORKS.items():
        print(f"\n  {cor(f'── {cat} ──', C.BOLD + C.BLUE)}")
        for modelo, dados in fabricantes.items():
            creds = dados.get("creds", "")
            risco = dados.get("risco", "")
            r_badge = badge_risco(risco)
            parts = creds.split("  ")
            user = next((p.replace("user:", "") for p in parts if "user:" in p), "?")
            pwd  = next((p.replace("pass:", "") for p in parts if "pass:" in p), "?")
            proto= next((p.replace("proto:", "") for p in parts if "proto:" in p), "?")

            cor_pwd = C.RED if pwd not in ["(vazia)", "?"] else C.YELLOW
            print(
                f"  {modelo:<45}"
                f"{cor(user, C.CYAN):<25}"
                f"{cor(pwd, cor_pwd):<30}"
                f"{cor(proto, C.DIM):<20}"
                f" {r_badge}"
            )

# ─────────────────────────────────────────────────────────────────────────────
# MENU PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def menu():
    while True:
        cabecalho()

        print(cor("  MENU PRINCIPAL — ESCOLHE UMA OPÇÃO", C.BOLD + C.WHITE))
        print()

        opcoes = [
            ("1",  "Estatísticas da base de dados de dorks"),
            ("2",  "Listar TODOS os dorks de Login (20 categorias)"),
            ("3",  "Listar só dorks de risco CRÍTICO (login)"),
            ("4",  "Listar TODOS os dorks por Fabricante/Modelo"),
            ("5",  "Pesquisa rápida por fabricante/tecnologia"),
            ("6",  "Tabela de credenciais padrão (todos os fabricantes)"),
            ("7",  "Guia de Defesa — Proteção de Login Pages"),
            ("8",  "Glossário técnico completo"),
            ("9",  "Exportar TODOS os dorks para JSON"),
            ("10", "Exportar TODOS os dorks para TXT (legível)"),
            ("0",  "Sair"),
        ]

        for k, desc in opcoes:
            c2 = C.CYAN if k != "0" else C.DIM
            print(f"    {cor(f'[{k:2s}]', c2)}  {desc}")

        print()
        try:
            escolha = input(cor("  → Escolhe uma opção: ", C.BOLD)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            info("Saindo. Usa estes dorks com responsabilidade e apenas em sistemas autorizados.")
            sys.exit(0)

        if escolha == "1":
            mostrar_estatisticas()

        elif escolha == "2":
            listar_login_dorks()

        elif escolha == "3":
            listar_login_dorks(filtro_risco="CRÍTICO")

        elif escolha == "4":
            listar_fabricantes_dorks()

        elif escolha == "5":
            try:
                termo = input(cor("  → Termo de pesquisa (ex: hikvision, cisco, mysql, vpn): ", C.BOLD)).strip()
                if termo:
                    pesquisa_rapida(termo)
            except (KeyboardInterrupt, EOFError):
                pass

        elif escolha == "6":
            mostrar_credenciais_padrao()

        elif escolha == "7":
            mostrar_defesa()

        elif escolha == "8":
            mostrar_glossario()

        elif escolha == "9":
            caminho = f"/tmp/dorks_auditoria_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            exportar_json(caminho)

        elif escolha == "10":
            caminho = f"/tmp/dorks_auditoria_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            exportar_texto(caminho)

        elif escolha == "0":
            print()
            info("Saindo. Usa estes dorks apenas em auditorias autorizadas.")
            print()
            sys.exit(0)

        else:
            aviso("Opção inválida. Escolhe entre 0 e 10.")
            time.sleep(1)
            continue

        try:
            input(cor("\n  → Prima ENTER para voltar ao menu...", C.DIM))
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# PONTO DE ENTRADA
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("--all", "--tudo"):
            cabecalho()
            mostrar_estatisticas()
            listar_login_dorks()
            listar_fabricantes_dorks()
            mostrar_defesa()
        elif arg == "--login":
            cabecalho()
            listar_login_dorks()
        elif arg == "--criticos":
            cabecalho()
            listar_login_dorks(filtro_risco="CRÍTICO")
        elif arg == "--fabricantes":
            cabecalho()
            listar_fabricantes_dorks()
        elif arg == "--credenciais":
            cabecalho()
            mostrar_credenciais_padrao()
        elif arg == "--defesa":
            cabecalho()
            mostrar_defesa()
        elif arg == "--glossario":
            cabecalho()
            mostrar_glossario()
        elif arg == "--exportar-json":
            cabecalho()
            exportar_json()
        elif arg == "--exportar-txt":
            cabecalho()
            exportar_texto()
        elif arg.startswith("--pesquisa="):
            termo = arg.split("=", 1)[1]
            cabecalho()
            pesquisa_rapida(termo)
        elif arg in ("--help", "-h"):
            cabecalho()
            print("  USO:")
            print("    python3 dorks_audit.py                    → Menu interactivo")
            print("    python3 dorks_audit.py --all              → Todos os dorks")
            print("    python3 dorks_audit.py --login            → Só dorks de login")
            print("    python3 dorks_audit.py --criticos         → Só risco CRÍTICO")
            print("    python3 dorks_audit.py --fabricantes      → Por fabricante/modelo")
            print("    python3 dorks_audit.py --credenciais      → Tabela de credenciais")
            print("    python3 dorks_audit.py --defesa           → Guia de defesa")
            print("    python3 dorks_audit.py --glossario        → Glossário técnico")
            print("    python3 dorks_audit.py --exportar-json    → Exportar JSON")
            print("    python3 dorks_audit.py --exportar-txt     → Exportar TXT")
            print("    python3 dorks_audit.py --pesquisa=cisco   → Pesquisa rápida")
            print()
        else:
            aviso(f"Argumento desconhecido: {arg}. Usa --help.")
    else:
        menu()
