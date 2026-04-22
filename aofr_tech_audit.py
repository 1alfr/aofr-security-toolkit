#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           AOFR TECH — AUDITORIA DEFENSIVA DE SEGURANÇA                     ║
║           Atitude · Orientação · Força · Resultados                         ║
║                                                                              ║
║  Fundador : Alfredo Ociola Francisco Romano — Luanda, Angola                ║
║  Versão   : 2.0.0                                                            ║
║  Stack    : Laravel 11 · Nginx · MySQL · Redis · PHP 8.3 · Cloudflare       ║
║                                                                              ║
║  AVISO LEGAL: USO EXCLUSIVO do proprietário da AOFR TECH para auditoria    ║
║  dos seus próprios sistemas. Aplicar estas técnicas em sistemas de          ║
║  terceiros sem autorização constitui crime nos termos da Lei 17/22 de       ║
║  Angola (Criminalidade Informática), Art. 4.º a 9.º.                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

Cobertura: 12 Departamentos
  DEP.01  Direcção Geral / Admin      → admin.aofr.tech
  DEP.02  Site Corporativo            → aofr.tech
  DEP.03  Blog / Content Hub          → blog.aofr.tech
  DEP.04  Comercial / CRM             → crm.aofr.tech
  DEP.05  Portal do Cliente           → portal.aofr.tech
  DEP.06  Financeiro / ERP            → erp.aofr.tech
  DEP.07  Técnico / Projectos         → erp.aofr.tech/projectos
  DEP.08  Recursos Humanos            → erp.aofr.tech/rh
  DEP.09  Suporte / Helpdesk          → suporte.aofr.tech
  DEP.10  API Gateway                 → api.aofr.tech
  DEP.11  Email / Comunicação         → mail.aofr.tech
  DEP.12  Monitorização / DevOps      → monitor.aofr.tech
"""

import sys
import json
import socket
import ssl
import subprocess
import datetime
import time
import urllib.request
import urllib.error
import urllib.parse
import http.client
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CORES ANSI
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

def cor(texto: str, cor: str) -> str:
    return f"{cor}{texto}{C.RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES DE DOMÍNIO
# ─────────────────────────────────────────────────────────────────────────────
DOMINIO_BASE = "aofr.tech"

SUBDOMINIOS = {
    "admin"   : "admin.aofr.tech",
    "site"    : "aofr.tech",
    "blog"    : "blog.aofr.tech",
    "crm"     : "crm.aofr.tech",
    "portal"  : "portal.aofr.tech",
    "erp"     : "erp.aofr.tech",
    "suporte" : "suporte.aofr.tech",
    "api"     : "api.aofr.tech",
    "mail"    : "mail.aofr.tech",
    "monitor" : "monitor.aofr.tech",
}

# Portas críticas que NÃO devem estar expostas publicamente
PORTAS_CRITICAS = {
    22   : "SSH",
    25   : "SMTP",
    80   : "HTTP",
    110  : "POP3",
    143  : "IMAP",
    443  : "HTTPS",
    465  : "SMTPS",
    587  : "SMTP-TLS",
    993  : "IMAPS",
    3000 : "Grafana",
    3306 : "MySQL ⚠ CRÍTICO",
    6379 : "Redis ⚠ CRÍTICO",
    7700 : "Meilisearch",
    8080 : "HTTP-Alt",
    9000 : "PHP-FPM ⚠ CRÍTICO",
    9090 : "Prometheus",
    9100 : "Node Exporter",
}

PORTAS_PUBLICAS_OK  = {80, 443, 25, 587, 465, 993, 143, 110}
PORTAS_NUNCA_ABERTAS = {3306, 6379, 9000}

# ─────────────────────────────────────────────────────────────────────────────
# DORKS POR DEPARTAMENTO
# ─────────────────────────────────────────────────────────────────────────────
DORKS = {
    "DEP.01 — Direcção Geral / Admin": {
        "shodan": [
            'hostname:"admin.aofr.tech"',
            'hostname:"admin.aofr.tech" port:443',
            'hostname:"admin.aofr.tech" port:80',
            'hostname:"admin.aofr.tech" http.title:"AOFR"',
            'hostname:"admin.aofr.tech" http.title:"Login"',
            'hostname:"admin.aofr.tech" http.title:"Dashboard"',
            'hostname:"admin.aofr.tech" http.component:"Laravel"',
            'hostname:"admin.aofr.tech" product:"nginx"',
            'hostname:"admin.aofr.tech" ssl.cert.expired:true',
            'hostname:"admin.aofr.tech" "X-Powered-By"',
        ],
        "google": [
            'site:admin.aofr.tech',
            'site:admin.aofr.tech inurl:login',
            'site:admin.aofr.tech inurl:dashboard',
            'site:admin.aofr.tech inurl:users',
            'site:admin.aofr.tech inurl:settings',
            'site:admin.aofr.tech inurl:reports',
            'site:aofr.tech inurl:telescope',
            'site:aofr.tech inurl:horizon',
            'site:aofr.tech "APP_DEBUG=true"',
            'site:aofr.tech "Stack trace" OR "Whoops"',
            'site:aofr.tech inurl:"nova"',
            'site:aofr.tech filetype:log',
            '"admin.aofr.tech" "password" OR "credentials"',
            '"AOFR TECH" "admin panel" OR "painel admin"',
        ],
        "alerta": (
            "REGRA DE OURO: admin.aofr.tech NUNCA deve aparecer indexado.\n"
            "  Se qualquer query retornar resultado → (1) meta noindex em todas as views,\n"
            "  (2) robots.txt Disallow:/admin, (3) restrição por IP no Nginx, (4) 2FA obrigatório."
        ),
    },
    "DEP.02 — Site Corporativo": {
        "shodan": [
            'hostname:"aofr.tech"',
            'hostname:"aofr.tech" port:80',
            'hostname:"aofr.tech" port:443',
            'hostname:"aofr.tech" http.title:"AOFR TECH"',
            'hostname:"aofr.tech" http.component:"Laravel"',
            'hostname:"aofr.tech" http.component:"Vue.js"',
            'hostname:"aofr.tech" http.component:"TailwindCSS"',
            'hostname:"aofr.tech" product:"nginx"',
            'ssl.cert.subject.cn:"aofr.tech"',
            'ssl.cert.subject.cn:"*.aofr.tech"',
            'hostname:"aofr.tech" ssl.version:"TLSv1"',
            'hostname:"aofr.tech" ssl.version:"TLSv1.1"',
            'hostname:"aofr.tech" ssl.cert.expired:true',
            'hostname:"aofr.tech" "server: nginx/1"',
            'hostname:"aofr.tech" "X-Powered-By: PHP"',
        ],
        "google": [
            'site:aofr.tech',
            'site:aofr.tech -www',
            'site:aofr.tech inurl:servicos',
            'site:aofr.tech inurl:portfolio',
            'site:aofr.tech inurl:contacto',
            'site:aofr.tech inurl:orcamento',
            'site:aofr.tech inurl:carreiras',
            'site:aofr.tech filetype:pdf',
            'site:aofr.tech filetype:docx',
            'site:aofr.tech filetype:env',
            'site:aofr.tech filetype:sql',
            'site:aofr.tech filetype:bak',
            'site:aofr.tech filetype:log',
            'site:aofr.tech inurl:".git"',
            'site:aofr.tech inurl:"storage"',
            'site:aofr.tech inurl:"vendor"',
            'site:aofr.tech inurl:"composer.json"',
            'site:aofr.tech inurl:"phpinfo"',
            'site:aofr.tech "Index of /"',
            '"aofr.tech" "Laravel" site:stackoverflow.com OR site:github.com',
        ],
        "alerta": (
            "SEO vs SEGURANÇA: Serviços, portfolio, contacto = indexar.\n"
            "  .env, /storage, /vendor, /admin = NUNCA indexar.\n"
            "  Verifica mensalmente com site:aofr.tech."
        ),
    },
    "DEP.03 — Blog / Content Hub": {
        "shodan": [
            'hostname:"blog.aofr.tech"',
            'hostname:"blog.aofr.tech" port:443',
            'hostname:"blog.aofr.tech" http.component:"Laravel"',
            'hostname:"blog.aofr.tech" http.title:"Blog"',
            'hostname:"blog.aofr.tech" http.title:"AOFR"',
            'hostname:"blog.aofr.tech" ssl.cert.expired:true',
            'hostname:"blog.aofr.tech" "X-Powered-By"',
            'hostname:"blog.aofr.tech" product:"nginx"',
            'hostname:"blog.aofr.tech" http.title:"Editor"',
            'hostname:"blog.aofr.tech" inurl:"/admin/posts"',
            'hostname:"blog.aofr.tech" inurl:"/admin/articles"',
        ],
        "google": [
            'site:blog.aofr.tech',
            'site:blog.aofr.tech inurl:admin',
            'site:blog.aofr.tech inurl:login',
            'site:blog.aofr.tech inurl:dashboard',
            'site:blog.aofr.tech inurl:draft',
            'site:blog.aofr.tech inurl:preview',
            'site:blog.aofr.tech filetype:xml',
            'site:blog.aofr.tech inurl:feed',
            'site:blog.aofr.tech inurl:sitemap',
            '"blog.aofr.tech" "newsletter"',
            '"blog.aofr.tech" "unsubscribe" email',
            '"AOFR TECH" "blog" site:linkedin.com OR site:facebook.com',
            '"aofr.tech" "artigo" OR "tutorial" OR "guia"',
        ],
        "alerta": (
            "BLOG: Artigos publicados devem estar indexados.\n"
            "  O que NÃO deve aparecer: rascunhos (/draft), área de login, e-mails\n"
            "  de subscritores da newsletter, e editor de texto do admin."
        ),
    },
    "DEP.04 — Comercial / CRM": {
        "shodan": [
            'hostname:"crm.aofr.tech"',
            'hostname:"crm.aofr.tech" port:443',
            'hostname:"crm.aofr.tech" port:80',
            'hostname:"crm.aofr.tech" http.title:"CRM"',
            'hostname:"crm.aofr.tech" http.title:"Login"',
            'hostname:"crm.aofr.tech" http.title:"Leads"',
            'hostname:"crm.aofr.tech" http.title:"Pipeline"',
            'hostname:"crm.aofr.tech" http.component:"Livewire"',
            'hostname:"crm.aofr.tech" ssl.cert.expired:true',
            'hostname:"crm.aofr.tech" "X-Powered-By"',
        ],
        "google": [
            'site:crm.aofr.tech',
            'site:crm.aofr.tech inurl:leads',
            'site:crm.aofr.tech inurl:clients',
            'site:crm.aofr.tech inurl:quotes',
            'site:crm.aofr.tech inurl:pipeline',
            'site:crm.aofr.tech inurl:login',
            'site:crm.aofr.tech filetype:csv',
            'site:crm.aofr.tech filetype:xlsx',
            'site:crm.aofr.tech filetype:pdf',
            '"crm.aofr.tech" "leads" OR "clientes" OR "pipeline"',
            '"crm.aofr.tech" "orçamento" OR "proposta" filetype:pdf',
            '"AOFR TECH" "proposta comercial" filetype:pdf',
            '"AOFR TECH" "ORC-2026" OR "orçamento"',
            'site:aofr.tech "cliente" "email" "telefone"',
        ],
        "alerta": (
            "DADOS COMERCIAIS SÃO CONFIDENCIAIS: Violação da Lei de Protecção\n"
            "  de Dados (Lei 22/11). O CRM deve ser inacessível sem autenticação\n"
            "  e nunca indexado pelo Google."
        ),
    },
    "DEP.05 — Portal do Cliente": {
        "shodan": [
            'hostname:"portal.aofr.tech"',
            'hostname:"portal.aofr.tech" port:443',
            'hostname:"portal.aofr.tech" port:80',
            'hostname:"portal.aofr.tech" http.title:"Portal"',
            'hostname:"portal.aofr.tech" http.title:"Client Portal"',
            'hostname:"portal.aofr.tech" http.title:"Login"',
            'hostname:"portal.aofr.tech" http.component:"Vue.js"',
            'hostname:"portal.aofr.tech" http.component:"Inertia"',
            'hostname:"portal.aofr.tech" ssl.cert.expired:true',
            'hostname:"portal.aofr.tech" "X-Powered-By"',
            'hostname:"portal.aofr.tech" port:3306',
        ],
        "google": [
            'site:portal.aofr.tech',
            'site:portal.aofr.tech inurl:projects',
            'site:portal.aofr.tech inurl:invoices',
            'site:portal.aofr.tech inurl:documents',
            'site:portal.aofr.tech inurl:tickets',
            'site:portal.aofr.tech inurl:messages',
            'site:portal.aofr.tech inurl:dashboard',
            'site:portal.aofr.tech inurl:profile',
            'site:portal.aofr.tech inurl:api-keys',
            'site:portal.aofr.tech filetype:pdf',
            'site:portal.aofr.tech "FAT-2026"',
            'site:portal.aofr.tech "invoice" OR "factura"',
            '"portal.aofr.tech" "token" OR "api_key"',
            '"portal.aofr.tech" "password reset" OR "forgot password"',
        ],
        "alerta": (
            "PORTAL: Toda a área autenticada deve ter robots noindex.\n"
            "  Tokens de API expostos são EMERGÊNCIA — invalida imediatamente\n"
            "  e notifica o cliente."
        ),
    },
    "DEP.06 — Financeiro / ERP": {
        "shodan": [
            'hostname:"erp.aofr.tech"',
            'hostname:"erp.aofr.tech" port:443',
            'hostname:"erp.aofr.tech" http.title:"ERP"',
            'hostname:"erp.aofr.tech" http.title:"Financeiro"',
            'hostname:"erp.aofr.tech" http.title:"Invoices"',
            'hostname:"erp.aofr.tech" http.title:"Dashboard"',
            'hostname:"erp.aofr.tech" http.component:"Livewire"',
            'hostname:"erp.aofr.tech" ssl.cert.expired:true',
            'hostname:"erp.aofr.tech" port:3306',
            'hostname:"erp.aofr.tech" "X-Powered-By: PHP"',
        ],
        "google": [
            'site:erp.aofr.tech',
            'site:erp.aofr.tech inurl:invoices',
            'site:erp.aofr.tech inurl:payments',
            'site:erp.aofr.tech inurl:financial',
            'site:erp.aofr.tech inurl:reports',
            'site:erp.aofr.tech inurl:cashflow',
            'site:erp.aofr.tech filetype:pdf',
            'site:erp.aofr.tech filetype:xlsx',
            'site:erp.aofr.tech filetype:csv',
            '"erp.aofr.tech" "FAT-2026" OR "REC-2026"',
            '"erp.aofr.tech" "revenue" OR "receita" OR "lucro"',
            '"AOFR TECH" "annual report" OR "relatório anual"',
            '"AOFR TECH" "NIF" OR "contribuinte" filetype:pdf',
            '"aofr.tech" "payoneer" OR "wise" OR "transferência"',
        ],
        "alerta": (
            "FINANCEIRO É CRÍTICO: Dados de facturação, receita e pagamentos\n"
            "  são altamente confidenciais. Activa 2FA obrigatório para todo\n"
            "  o acesso ao módulo financeiro."
        ),
    },
    "DEP.07 — Técnico / Projectos": {
        "shodan": [
            'hostname:"aofr.tech" port:22',
            'hostname:"aofr.tech" port:8080',
            'hostname:"aofr.tech" port:9000',
            'hostname:"aofr.tech" port:7700',
            'hostname:"aofr.tech" port:6379',
            'hostname:"aofr.tech" port:3306',
            'hostname:"aofr.tech" http.title:"Horizon"',
            'hostname:"aofr.tech" http.title:"Telescope"',
            'hostname:"aofr.tech" http.title:"Meilisearch"',
            'hostname:"monitor.aofr.tech"',
            'hostname:"monitor.aofr.tech" http.title:"Grafana"',
            'hostname:"monitor.aofr.tech" http.title:"Zabbix"',
        ],
        "google": [
            'site:github.com "aofr-tech"',
            'site:github.com "aofr.tech"',
            'site:github.com "AOFR TECH" "laravel"',
            'site:github.com "aofr" "DB_PASSWORD" OR "APP_KEY"',
            'site:github.com "aofr" ".env" filetype:env',
            'site:gitlab.com "aofr-tech"',
            'site:bitbucket.org "aofr"',
            'site:aofr.tech inurl:telescope',
            'site:aofr.tech inurl:horizon',
            'site:aofr.tech "debug" OR "stack trace"',
            'site:aofr.tech inurl:"_debugbar"',
            '"aofr.tech" "composer.lock" OR "package.json"',
            '"aofr.tech" "laravel" "version"',
            '"AOFR TECH" "GitHub" OR "repositório" OR "código"',
            'site:pastebin.com "aofr.tech"',
        ],
        "alerta": (
            "REPOSITÓRIOS: Garante que os repositórios GitHub são PRIVADOS.\n"
            "  Nunca commites .env, credenciais ou chaves de API.\n"
            "  Usa git-secrets ou .gitignore correcto."
        ),
    },
    "DEP.08 — Recursos Humanos": {
        "shodan": [
            'hostname:"erp.aofr.tech" http.title:"RH"',
            'hostname:"erp.aofr.tech" http.title:"Recursos Humanos"',
            'hostname:"erp.aofr.tech" http.title:"Employees"',
            'hostname:"erp.aofr.tech" http.title:"Funcionários"',
            'hostname:"erp.aofr.tech" ssl.cert.expired:true',
            'hostname:"erp.aofr.tech" port:443 http.status:200',
        ],
        "google": [
            'site:erp.aofr.tech inurl:employees',
            'site:erp.aofr.tech inurl:staff',
            'site:erp.aofr.tech inurl:rh',
            'site:erp.aofr.tech inurl:contracts',
            'site:erp.aofr.tech inurl:payroll',
            'site:erp.aofr.tech inurl:salary',
            'site:erp.aofr.tech filetype:pdf "contrato"',
            '"AOFR TECH" "funcionário" OR "trabalhador" filetype:pdf',
            '"AOFR TECH" "BI:" OR "NIF:" OR "NISS:"',
            '"AOFR TECH" site:linkedin.com',
            '"AOFR TECH" "team" OR "equipa" site:aofr.tech',
            '"aofr.tech" "salário" OR "salary" OR "remuneração"',
            '"AOFR TECH" "recrutamento" OR "vaga" OR "emprego"',
        ],
        "alerta": (
            "DADOS DE RH SÃO ULTRA-SENSÍVEIS: BI, NIF, NISS, salários e contratos\n"
            "  são protegidos pela Lei 22/11 de Angola. Exposição pode gerar processo\n"
            "  criminal. Módulo RH com 2FA obrigatório."
        ),
    },
    "DEP.09 — Suporte / Helpdesk": {
        "shodan": [
            'hostname:"suporte.aofr.tech"',
            'hostname:"suporte.aofr.tech" port:443',
            'hostname:"suporte.aofr.tech" port:80',
            'hostname:"suporte.aofr.tech" http.title:"Suporte"',
            'hostname:"suporte.aofr.tech" http.title:"Helpdesk"',
            'hostname:"suporte.aofr.tech" http.title:"Tickets"',
            'hostname:"suporte.aofr.tech" http.component:"Livewire"',
            'hostname:"suporte.aofr.tech" ssl.cert.expired:true',
            'hostname:"suporte.aofr.tech" "X-Powered-By"',
        ],
        "google": [
            'site:suporte.aofr.tech',
            'site:suporte.aofr.tech inurl:tickets',
            'site:suporte.aofr.tech inurl:ticket',
            'site:suporte.aofr.tech inurl:"TKT-2026"',
            'site:suporte.aofr.tech inurl:open',
            'site:suporte.aofr.tech inurl:admin',
            'site:suporte.aofr.tech inurl:agents',
            '"suporte.aofr.tech" "TKT-" OR "ticket"',
            '"AOFR TECH" "support" "complaint" OR "problema"',
            '"suporte.aofr.tech" "senha" OR "password" OR "credenciais"',
            '"AOFR TECH" suporte site:reclameaqui.com.br OR site:complain.biz',
            '"AOFR TECH" "reclamação" OR "má qualidade"',
            '"AOFR TECH" site:trustpilot.com OR site:google.com/maps',
        ],
        "alerta": (
            "SUPORTE E REPUTAÇÃO: Monitoriza também o que os clientes dizem online.\n"
            "  Plataformas de reclamação e reviews devem ser verificadas mensalmente."
        ),
    },
    "DEP.10 — API Gateway": {
        "shodan": [
            'hostname:"api.aofr.tech"',
            'hostname:"api.aofr.tech" port:443',
            'hostname:"api.aofr.tech" port:80',
            'hostname:"api.aofr.tech" http.title:"API"',
            'hostname:"api.aofr.tech" http.title:"Swagger"',
            'hostname:"api.aofr.tech" http.title:"API Documentation"',
            'hostname:"api.aofr.tech" http.component:"Swagger UI"',
            'hostname:"api.aofr.tech" "/api/documentation"',
            'hostname:"api.aofr.tech" ssl.cert.expired:true',
            'hostname:"api.aofr.tech" port:8080',
            'hostname:"api.aofr.tech" "Access-Control-Allow-Origin: *"',
            'hostname:"api.aofr.tech" "X-RateLimit-Limit"',
            'hostname:"api.aofr.tech" http.status:200 "/api/v1/users"',
            'hostname:"api.aofr.tech" http.status:200 "/api/v1/admin"',
        ],
        "google": [
            'site:api.aofr.tech',
            'site:api.aofr.tech inurl:documentation',
            'site:api.aofr.tech inurl:swagger',
            'site:api.aofr.tech inurl:v1',
            'site:api.aofr.tech inurl:v2',
            'site:api.aofr.tech "/api/v1/admin"',
            '"api.aofr.tech" "Bearer" OR "token" OR "api_key"',
            '"api.aofr.tech" "Authorization:"',
            'site:aofr.tech inurl:"/api/v1/auth/login"',
            'site:aofr.tech inurl:"/api/v1/admin"',
            '"aofr.tech" "api_token" OR "access_token" site:github.com',
            '"aofr.tech" "Authorization: Bearer" site:pastebin.com',
            '"AOFR TECH" "API" "documentation" OR "docs"',
            '"api.aofr.tech" site:stackoverflow.com',
        ],
        "alerta": (
            "API SECURITY: Swagger/OpenAPI deve estar protegido por autenticação\n"
            "  em produção. CORS 'Allow-Origin: *' é perigoso — restringe aos domínios\n"
            "  da AOFR TECH. Tokens comprometidos devem ser revogados imediatamente."
        ),
    },
    "DEP.11 — Email / Comunicação": {
        "shodan": [
            'hostname:"mail.aofr.tech"',
            'hostname:"mail.aofr.tech" port:25',
            'hostname:"mail.aofr.tech" port:587',
            'hostname:"mail.aofr.tech" port:465',
            'hostname:"mail.aofr.tech" port:993',
            'hostname:"mail.aofr.tech" port:143',
            'hostname:"mail.aofr.tech" port:110',
            'hostname:"mail.aofr.tech" "220" smtp',
            'hostname:"aofr.tech" mx:true',
            'hostname:"mail.aofr.tech" ssl.cert.expired:true',
            'hostname:"mail.aofr.tech" "open relay"',
        ],
        "google": [
            '"@aofr.tech" email',
            '"admin@aofr.tech" OR "info@aofr.tech" OR "suporte@aofr.tech"',
            '"@aofr.tech" site:linkedin.com',
            '"@aofr.tech" site:facebook.com',
            '"@aofr.tech" site:github.com',
            '"@aofr.tech" "password" OR "senha"',
            '"aofr.tech" inurl:unsubscribe',
            '"AOFR TECH" "newsletter" email',
            'site:mail.aofr.tech',
            'site:mail.aofr.tech inurl:webmail',
            'site:mail.aofr.tech inurl:roundcube OR inurl:rainloop',
            '"mail.aofr.tech" "login" OR "webmail"',
        ],
        "alerta": (
            "EMAIL: Verifica SPF, DKIM e DMARC configurados para aofr.tech.\n"
            "  Isso previne que alguém envie email em teu nome.\n"
            "  Verifica em: mxtoolbox.com/SuperTool.aspx"
        ),
    },
    "DEP.12 — Monitorização / DevOps": {
        "shodan": [
            'hostname:"monitor.aofr.tech"',
            'hostname:"monitor.aofr.tech" port:3000',
            'hostname:"monitor.aofr.tech" port:8080',
            'hostname:"monitor.aofr.tech" port:9090',
            'hostname:"monitor.aofr.tech" http.title:"Grafana"',
            'hostname:"monitor.aofr.tech" http.title:"Zabbix"',
            'hostname:"monitor.aofr.tech" http.title:"Uptime"',
            'hostname:"aofr.tech" http.title:"Telescope" port:443',
            'hostname:"aofr.tech" http.title:"Laravel Horizon"',
            'hostname:"aofr.tech" port:9100',
        ],
        "google": [
            'site:monitor.aofr.tech',
            'site:monitor.aofr.tech inurl:grafana',
            'site:monitor.aofr.tech inurl:zabbix',
            'site:github.com "aofr-tech" ".github/workflows"',
            'site:github.com "aofr-tech" "deploy.yml"',
            'site:github.com "aofr-tech" "secrets"',
            '"aofr.tech" site:github.com "workflow"',
            '"AOFR TECH" "docker-compose" site:github.com',
            '"AOFR TECH" "server" "IP" "SSH"',
            '"aofr.tech" "Digital Ocean" OR "Linode" OR "AWS"',
            'site:aofr.tech "phpinfo()"',
            'site:aofr.tech "server status" OR "mod_status"',
        ],
        "alerta": (
            "DEVOPS: Grafana e Zabbix em monitor.aofr.tech devem exigir login.\n"
            "  Nunca exponhas IPs de servidor, configurações de CI/CD ou segredos\n"
            "  do GitHub Actions publicamente."
        ),
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# TABELA DE RESPOSTA A INCIDENTES
# ─────────────────────────────────────────────────────────────────────────────
TABELA_RESPOSTA = [
    {
        "achado"    : ".env indexado no Google",
        "gravidade" : "CRÍTICA",
        "acao"      : "Apaga ficheiro. Muda TODOS os secrets. Pede remoção ao Google.",
        "prazo"     : "< 1 hora",
    },
    {
        "achado"    : "MySQL port:3306 aberto no Shodan",
        "gravidade" : "CRÍTICA",
        "acao"      : "sudo ufw deny 3306. bind-address=127.0.0.1 no my.cnf.",
        "prazo"     : "< 1 hora",
    },
    {
        "achado"    : "Redis port:6379 aberto",
        "gravidade" : "CRÍTICA",
        "acao"      : "sudo ufw deny 6379. bind 127.0.0.1 no redis.conf.",
        "prazo"     : "< 1 hora",
    },
    {
        "achado"    : "Ficheiro de log indexado",
        "gravidade" : "ALTA",
        "acao"      : "Bloqueia no Nginx. Apaga do storage. Pede remoção Google.",
        "prazo"     : "< 4 horas",
    },
    {
        "achado"    : "APP_DEBUG=true em produção",
        "gravidade" : "ALTA",
        "acao"      : "Muda para false no .env. php artisan config:cache.",
        "prazo"     : "< 2 horas",
    },
    {
        "achado"    : "Painel admin indexado",
        "gravidade" : "ALTA",
        "acao"      : "Adiciona noindex. Robots.txt. Restrição por IP no Nginx.",
        "prazo"     : "< 4 horas",
    },
    {
        "achado"    : "Token/API key exposto no GitHub",
        "gravidade" : "ALTA",
        "acao"      : "Revoga token imediatamente. Gera novo. Audita acessos.",
        "prazo"     : "< 1 hora",
    },
    {
        "achado"    : "TLS 1.0/1.1 activo",
        "gravidade" : "MÉDIA",
        "acao"      : "Desactiva no nginx.conf: ssl_protocols TLSv1.2 TLSv1.3.",
        "prazo"     : "< 24 horas",
    },
    {
        "achado"    : "Versão PHP/Nginx exposta",
        "gravidade" : "MÉDIA",
        "acao"      : "expose_php=Off. server_tokens off. Reinicia serviços.",
        "prazo"     : "< 24 horas",
    },
    {
        "achado"    : "Sub-domínio desconhecido no Shodan",
        "gravidade" : "MÉDIA",
        "acao"      : "Verifica se é legítimo. Remove DNS se não for.",
        "prazo"     : "< 24 horas",
    },
    {
        "achado"    : "Certificado SSL expirado",
        "gravidade" : "MÉDIA",
        "acao"      : "Renova certificado (Let's Encrypt: certbot renew).",
        "prazo"     : "< 4 horas",
    },
    {
        "achado"    : "Dados de cliente indexados",
        "gravidade" : "ALTA",
        "acao"      : "Remove páginas. Pede remoção Google. Notifica o cliente.",
        "prazo"     : "< 4 horas",
    },
    {
        "achado"    : "Email da empresa em data breach",
        "gravidade" : "ALTA",
        "acao"      : "Muda password. Activa 2FA. Verifica acessos recentes.",
        "prazo"     : "< 2 horas",
    },
    {
        "achado"    : "Open relay SMTP detectado",
        "gravidade" : "ALTA",
        "acao"      : "Configura restrições SMTP. Verifica se não estás em blacklist.",
        "prazo"     : "< 4 horas",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# UTILITÁRIOS DE IMPRESSÃO
# ─────────────────────────────────────────────────────────────────────────────
LINHA_LARGA  = "═" * 78
LINHA_MEDIA  = "─" * 78
LINHA_CURTA  = "·" * 78

def cabecalho():
    print()
    print(cor(LINHA_LARGA, C.CYAN))
    print(cor("  AOFR TECH — AUDITORIA DEFENSIVA DE SEGURANÇA", C.BOLD + C.CYAN))
    print(cor("  Atitude · Orientação · Força · Resultados", C.CYAN))
    print(cor(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — Luanda, Angola", C.DIM))
    print(cor(LINHA_LARGA, C.CYAN))
    print()

def titulo_secao(texto: str, indice: int = 0):
    print()
    print(cor(LINHA_MEDIA, C.BLUE))
    prefixo = f"[{indice:02d}] " if indice else "    "
    print(cor(f"{prefixo}{texto}", C.BOLD + C.BLUE))
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
    t = cor(f"[{tipo:6s}]", C.DIM)
    print(f"      {t}  {query}")

def nota_alerta(texto: str):
    print()
    print(cor("  ┌─ NOTA ─────────────────────────────────────────────────────────────────", C.YELLOW))
    for linha in texto.split("\n"):
        print(cor(f"  │  {linha}", C.YELLOW))
    print(cor("  └─────────────────────────────────────────────────────────────────────────", C.YELLOW))

# ─────────────────────────────────────────────────────────────────────────────
# VERIFICAÇÕES TÉCNICAS REAIS
# ─────────────────────────────────────────────────────────────────────────────

def verificar_porta(host: str, porta: int, timeout: float = 2.0) -> bool:
    """Tenta abrir uma conexão TCP para host:porta."""
    try:
        with socket.create_connection((host, porta), timeout=timeout):
            return True
    except Exception:
        return False

def verificar_ssl(host: str) -> dict:
    """Verifica certificado SSL e versão TLS do host."""
    resultado = {
        "expira"      : None,
        "dias_restantes": None,
        "expirado"    : False,
        "cn"          : None,
        "issuer"      : None,
        "versao_tls"  : None,
        "erro"        : None,
    }
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=5),
            server_hostname=host,
        )
        cert = conn.getpeercert()
        versao = conn.version()
        conn.close()

        not_after = cert.get("notAfter", "")
        if not_after:
            expira = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            resultado["expira"]         = expira.strftime("%Y-%m-%d")
            resultado["dias_restantes"] = (expira - datetime.datetime.utcnow()).days
            resultado["expirado"]       = resultado["dias_restantes"] < 0

        for campo in cert.get("subject", []):
            for k, v in campo:
                if k == "commonName":
                    resultado["cn"] = v

        for campo in cert.get("issuer", []):
            for k, v in campo:
                if k == "organizationName":
                    resultado["issuer"] = v

        resultado["versao_tls"] = versao
    except ssl.SSLCertVerificationError as e:
        resultado["erro"] = f"Verificação SSL falhou: {e}"
    except Exception as e:
        resultado["erro"] = str(e)

    return resultado

def verificar_headers_http(host: str, caminho: str = "/", porta: int = 443) -> dict:
    """Obtém headers HTTP de resposta."""
    resultado = {
        "status"         : None,
        "server"         : None,
        "x_powered_by"   : None,
        "x_frame_options": None,
        "hsts"           : None,
        "csp"            : None,
        "x_content_type" : None,
        "erro"           : None,
    }
    try:
        if porta == 443:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port=porta, timeout=5, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port=porta, timeout=5)

        conn.request("HEAD", caminho, headers={"User-Agent": "AOFR-AuditBot/2.0"})
        resp = conn.getresponse()
        conn.close()

        resultado["status"]          = resp.status
        resultado["server"]          = resp.getheader("Server", "")
        resultado["x_powered_by"]    = resp.getheader("X-Powered-By", "")
        resultado["x_frame_options"] = resp.getheader("X-Frame-Options", "")
        resultado["hsts"]            = resp.getheader("Strict-Transport-Security", "")
        resultado["csp"]             = resp.getheader("Content-Security-Policy", "")
        resultado["x_content_type"]  = resp.getheader("X-Content-Type-Options", "")
    except Exception as e:
        resultado["erro"] = str(e)

    return resultado

def resolver_dns(host: str) -> Optional[str]:
    """Resolve um hostname para IP."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def verificar_dns_email(dominio: str) -> dict:
    """Verifica registos SPF, DKIM e DMARC via dig."""
    resultado = {"spf": None, "dmarc": None, "erro": None}
    try:
        # SPF
        r = subprocess.run(
            ["dig", "+short", "TXT", dominio],
            capture_output=True, text=True, timeout=10
        )
        for linha in r.stdout.splitlines():
            if "v=spf1" in linha:
                resultado["spf"] = linha.strip('"')
                break

        # DMARC
        r2 = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{dominio}"],
            capture_output=True, text=True, timeout=10
        )
        for linha in r2.stdout.splitlines():
            if "v=DMARC1" in linha:
                resultado["dmarc"] = linha.strip('"')
                break
    except FileNotFoundError:
        resultado["erro"] = "dig não instalado"
    except Exception as e:
        resultado["erro"] = str(e)

    return resultado

# ─────────────────────────────────────────────────────────────────────────────
# MÓDULOS DE AUDITORIA
# ─────────────────────────────────────────────────────────────────────────────

def auditoria_portas(resultados: list):
    titulo_secao("VERIFICAÇÃO DE PORTAS EXPOSTAS", 1)
    info("A testar portas críticas em todos os sub-domínios...")
    info("(portas abertas onde NÃO deveriam ser abertas são marcadas como ⚠)\n")

    for nome, host in SUBDOMINIOS.items():
        ip = resolver_dns(host)
        if ip is None:
            aviso(f"{host:<30} → DNS não resolve (sub-domínio inactivo ou não existe)")
            continue

        subtitulo(f"{host}  [{ip}]")
        for porta, servico in sorted(PORTAS_CRITICAS.items()):
            aberta = verificar_porta(host, porta)
            if aberta:
                if porta in PORTAS_NUNCA_ABERTAS:
                    erro(f"porta {porta:5d}  {servico:<20}  ABERTA → EMERGÊNCIA! Deve estar fechada ao público")
                    resultados.append({
                        "achado"   : f"{servico} port:{porta} exposto em {host}",
                        "gravidade": "CRÍTICA",
                        "host"     : host,
                    })
                elif porta in PORTAS_PUBLICAS_OK:
                    ok(f"porta {porta:5d}  {servico:<20}  aberta (esperado)")
                else:
                    aviso(f"porta {porta:5d}  {servico:<20}  aberta — verificar se é intencional")
                    resultados.append({
                        "achado"   : f"{servico} port:{porta} exposto em {host}",
                        "gravidade": "MÉDIA",
                        "host"     : host,
                    })

def auditoria_ssl(resultados: list):
    titulo_secao("VERIFICAÇÃO DE CERTIFICADOS SSL / TLS", 2)
    info("A verificar certificados SSL em todos os sub-domínios HTTPS...\n")

    for nome, host in SUBDOMINIOS.items():
        ip = resolver_dns(host)
        if ip is None:
            continue

        resultado = verificar_ssl(host)

        if resultado["erro"]:
            aviso(f"{host:<32} → Erro: {resultado['erro']}")
            continue

        subtitulo(host)

        if resultado["expirado"]:
            erro(f"Certificado EXPIRADO há {abs(resultado['dias_restantes'])} dias!")
            resultados.append({
                "achado"   : f"Certificado SSL expirado em {host}",
                "gravidade": "MÉDIA",
                "host"     : host,
            })
        elif resultado["dias_restantes"] is not None and resultado["dias_restantes"] < 30:
            aviso(f"Certificado expira em {resultado['dias_restantes']} dias! ({resultado['expira']})")
            resultados.append({
                "achado"   : f"Certificado SSL expira em breve em {host}",
                "gravidade": "MÉDIA",
                "host"     : host,
            })
        else:
            ok(f"Certificado válido até {resultado['expira']} ({resultado['dias_restantes']} dias)")

        if resultado["versao_tls"] in ("TLSv1", "TLSv1.1"):
            erro(f"TLS desactualizado: {resultado['versao_tls']} — desactiva no nginx.conf!")
            resultados.append({
                "achado"   : f"TLS desactualizado ({resultado['versao_tls']}) em {host}",
                "gravidade": "MÉDIA",
                "host"     : host,
            })
        elif resultado["versao_tls"]:
            ok(f"Versão TLS: {resultado['versao_tls']}")

        if resultado["cn"]:
            info(f"CN: {resultado['cn']}  |  Emissor: {resultado['issuer']}")

def auditoria_headers(resultados: list):
    titulo_secao("VERIFICAÇÃO DE HEADERS DE SEGURANÇA HTTP", 3)
    info("A verificar headers de segurança nos principais sub-domínios...\n")

    hosts_prioritarios = [
        ("site",    "aofr.tech",       "/",       443),
        ("admin",   "admin.aofr.tech", "/",       443),
        ("api",     "api.aofr.tech",   "/api/v1", 443),
        ("portal",  "portal.aofr.tech","/",       443),
        ("crm",     "crm.aofr.tech",   "/",       443),
        ("erp",     "erp.aofr.tech",   "/",       443),
        ("suporte", "suporte.aofr.tech","/",      443),
    ]

    for nome, host, caminho, porta in hosts_prioritarios:
        ip = resolver_dns(host)
        if ip is None:
            continue

        h = verificar_headers_http(host, caminho, porta)
        subtitulo(f"{host}{caminho}")

        if h["erro"]:
            aviso(f"Não foi possível conectar: {h['erro']}")
            continue

        info(f"HTTP {h['status']}")

        # Server header — expõe versão
        if h["server"]:
            if any(v in (h["server"] or "") for v in ["nginx/", "Apache/", "PHP/"]):
                aviso(f"Server header expõe versão: {h['server']}  → server_tokens off;")
                resultados.append({
                    "achado"   : f"Versão PHP/Nginx exposta em {host}",
                    "gravidade": "MÉDIA",
                    "host"     : host,
                })
            else:
                ok(f"Server: {h['server']}")

        # X-Powered-By
        if h["x_powered_by"]:
            aviso(f"X-Powered-By presente: {h['x_powered_by']}  → expose_php=Off")
            resultados.append({
                "achado"   : f"X-Powered-By exposto em {host}",
                "gravidade": "MÉDIA",
                "host"     : host,
            })
        else:
            ok("X-Powered-By: ausente ✔")

        # HSTS
        if h["hsts"]:
            ok(f"HSTS: {h['hsts'][:60]}")
        else:
            aviso("HSTS ausente → adiciona Strict-Transport-Security no Nginx")

        # X-Frame-Options
        if h["x_frame_options"]:
            ok(f"X-Frame-Options: {h['x_frame_options']}")
        else:
            aviso("X-Frame-Options ausente → adiciona add_header X-Frame-Options DENY;")

        # X-Content-Type-Options
        if h["x_content_type"]:
            ok(f"X-Content-Type-Options: {h['x_content_type']}")
        else:
            aviso("X-Content-Type-Options ausente → add_header X-Content-Type-Options nosniff;")

def auditoria_dns_email(resultados: list):
    titulo_secao("VERIFICAÇÃO DNS — SPF · DKIM · DMARC", 4)
    info(f"A verificar registos de segurança de email para {DOMINIO_BASE}...\n")

    dns = verificar_dns_email(DOMINIO_BASE)

    if dns["erro"]:
        aviso(f"Não foi possível verificar DNS: {dns['erro']}")
        info("Verifica manualmente em: mxtoolbox.com/SuperTool.aspx")
        return

    subtitulo(f"Domínio: {DOMINIO_BASE}")

    if dns["spf"]:
        ok(f"SPF encontrado: {dns['spf'][:70]}")
    else:
        erro("SPF NÃO configurado! Qualquer um pode enviar email como @aofr.tech")
        resultados.append({
            "achado"   : "SPF não configurado para aofr.tech",
            "gravidade": "ALTA",
            "host"     : DOMINIO_BASE,
        })

    if dns["dmarc"]:
        ok(f"DMARC encontrado: {dns['dmarc'][:70]}")
    else:
        erro("DMARC NÃO configurado! Phishing com @aofr.tech é possível")
        resultados.append({
            "achado"   : "DMARC não configurado para aofr.tech",
            "gravidade": "ALTA",
            "host"     : DOMINIO_BASE,
        })

    info("Para verificar DKIM, consulta o painel do teu provedor de email")
    info("Ferramenta recomendada: mxtoolbox.com/SuperTool.aspx")

def auditoria_subdomains(resultados: list):
    titulo_secao("INVENTÁRIO DE SUB-DOMÍNIOS", 5)
    info("A resolver todos os sub-domínios conhecidos da AOFR TECH...\n")

    ativos  = []
    inativos = []

    for nome, host in SUBDOMINIOS.items():
        ip = resolver_dns(host)
        if ip:
            ativos.append((host, ip))
            ok(f"{host:<35} → {ip}")
        else:
            inativos.append(host)
            aviso(f"{host:<35} → não resolve")

    print()
    info(f"Sub-domínios activos : {len(ativos)}")
    info(f"Sub-domínios inactivos: {len(inativos)}")

    if inativos:
        print()
        aviso("Sub-domínios que não resolvem (podem ainda ser registados no DNS):")
        for h in inativos:
            print(f"       {h}")

def imprimir_dorks(resultados: list):
    titulo_secao("QUERIES SHODAN + GOOGLE — POR DEPARTAMENTO (200+ DORKS)", 6)
    info("Copia e executa estas queries no Shodan (shodan.io) e Google.\n")
    info("INSTRUÇÃO: Se qualquer query retornar resultado inesperado →")
    info("consulta a TABELA DE RESPOSTA A INCIDENTES (opção 7 do menu).\n")

    for idx, (dep, dados) in enumerate(DORKS.items(), start=1):
        titulo_secao(dep, idx)

        subtitulo("SHODAN")
        for q in dados["shodan"]:
            dork_linha("SHODAN", q)

        subtitulo("GOOGLE")
        for q in dados["google"]:
            dork_linha("GOOGLE", q)

        nota_alerta(dados["alerta"])

def imprimir_tabela_resposta():
    titulo_secao("TABELA DE RESPOSTA A INCIDENTES", 7)
    info("O que fazer quando encontras uma vulnerabilidade:\n")

    cores_gravidade = {
        "CRÍTICA": C.RED   + C.BOLD,
        "ALTA"   : C.RED,
        "MÉDIA"  : C.YELLOW,
        "BAIXA"  : C.GREEN,
    }

    print(f"  {'ACHADO':<42} {'GRAV.':<8} {'PRAZO':<12} ACÇÃO IMEDIATA")
    print(cor("  " + "─" * 110, C.DIM))

    for item in TABELA_RESPOSTA:
        g   = item["gravidade"]
        cor_g = cores_gravidade.get(g, C.WHITE)
        print(
            f"  {item['achado']:<42} "
            f"{cor(g, cor_g):<20} "
            f"{item['prazo']:<12} "
            f"{item['acao']}"
        )

def imprimir_glossario():
    titulo_secao("GLOSSÁRIO DE SEGURANÇA", 8)

    termos = {
        "CORS"        : "Cross-Origin Resource Sharing. 'Allow-Origin: *' permite qualquer domínio — perigoso em APIs autenticadas.",
        "Data Breach" : "Exposição não autorizada de dados. Verifica em haveibeenpwned.com.",
        "DKIM"        : "DomainKeys Identified Mail. Assinatura criptográfica nos emails.",
        "DMARC"       : "Combina SPF e DKIM contra uso fraudulento de email. DNS: _dmarc.aofr.tech.",
        "Dork Defensivo": "Query de pesquisa usada pelo proprietário para descobrir a sua exposição online.",
        "Google Search Console": "Ferramenta do Google para ver páginas indexadas e solicitar remoções.",
        "HSTS"        : "HTTP Strict Transport Security. Força HTTPS. Nginx: add_header Strict-Transport-Security 'max-age=63072000'.",
        "IP Whitelist": "Lista de IPs autorizados. Paineis admin devem ser acessíveis apenas ao teu IP fixo ou VPN.",
        "Lei 22/11"   : "Lei de Protecção de Dados Pessoais de Angola.",
        "Lei 17/22"   : "Criminalidade Informática de Angola. Art. 4.º a 9.º.",
        "Open Relay"  : "Servidor SMTP que reenvia emails de qualquer origem. Resulta em blacklist do IP.",
        "OSINT Defensivo": "Técnicas de inteligência de fontes abertas para descobrir e corrigir a própria exposição.",
        "Robots.txt"  : "Ficheiro /public/robots.txt que instrui motores de busca. NÃO é segurança real.",
        "Shodan Monitor": "Funcionalidade do Shodan que alerta quando o teu IP aparece em resultados.",
        "SPF"         : "Sender Policy Framework. Registo DNS que lista servidores autorizados a enviar email.",
        "SSL Labs Grade": "Pontuação A-F da Qualys SSL Labs. Meta AOFR TECH: nota A ou A+. ssllabs.com/ssltest",
        "2FA"         : "Autenticação em dois passos: password + código TOTP. Obrigatório em todos os paineis admin.",
        "UFW"         : "Uncomplicated Firewall no Ubuntu. Base: ufw default deny incoming && ufw allow 22,80,443.",
    }

    for termo, definicao in termos.items():
        print(f"\n  {cor(termo, C.BOLD + C.CYAN)}")
        print(f"     {definicao}")

def gerar_relatorio_json(resultados: list):
    """Gera um relatório JSON com os problemas encontrados."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_ficheiro = f"/tmp/aofr_tech_auditoria_{ts}.json"

    relatorio = {
        "empresa"        : "AOFR TECH",
        "auditor"        : "Alfredo Ociola Francisco Romano",
        "data_auditoria" : datetime.datetime.now().isoformat(),
        "dominio_base"   : DOMINIO_BASE,
        "total_problemas": len(resultados),
        "criticos"       : sum(1 for r in resultados if r.get("gravidade") == "CRÍTICA"),
        "altos"          : sum(1 for r in resultados if r.get("gravidade") == "ALTA"),
        "medios"         : sum(1 for r in resultados if r.get("gravidade") == "MÉDIA"),
        "problemas"      : resultados,
    }

    with open(nome_ficheiro, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, ensure_ascii=False, indent=2)

    return nome_ficheiro

def imprimir_resumo_final(resultados: list):
    print()
    print(cor(LINHA_LARGA, C.CYAN))
    print(cor("  RESUMO DA AUDITORIA", C.BOLD + C.CYAN))
    print(cor(LINHA_LARGA, C.CYAN))

    criticos = [r for r in resultados if r.get("gravidade") == "CRÍTICA"]
    altos    = [r for r in resultados if r.get("gravidade") == "ALTA"]
    medios   = [r for r in resultados if r.get("gravidade") == "MÉDIA"]

    print()
    if criticos:
        erro(f"Problemas CRÍTICOS  : {len(criticos)}")
        for r in criticos:
            print(cor(f"      → {r['achado']}  [{r.get('host','')}]", C.RED))
    else:
        ok("Nenhum problema CRÍTICO detectado nas verificações automáticas")

    if altos:
        aviso(f"Problemas ALTOS     : {len(altos)}")
        for r in altos:
            print(cor(f"      → {r['achado']}  [{r.get('host','')}]", C.YELLOW))
    else:
        ok("Nenhum problema ALTO detectado")

    if medios:
        info(f"Problemas MÉDIOS    : {len(medios)}")
        for r in medios:
            print(f"      → {r['achado']}  [{r.get('host','')}]")
    else:
        ok("Nenhum problema MÉDIO detectado")

    print()
    if resultados:
        ficheiro = gerar_relatorio_json(resultados)
        ok(f"Relatório JSON guardado: {ficheiro}")
    else:
        ok("Nenhum problema automático detectado — executa as dorks manualmente!")

    print()
    info("PRÓXIMOS PASSOS:")
    info("  1. Executa as dorks Shodan e Google (opção 4 do menu)")
    info("  2. Corrige os problemas detectados usando a Tabela de Resposta (opção 5)")
    info("  3. Agenda auditoria mensal: primeiro domingo de cada mês")
    info("  4. Activa Shodan Monitor para alertas automáticos")
    info("  5. Verifica haveibeenpwned.com para todos os emails @aofr.tech")
    print()
    print(cor("  AOFR TECH — Atitude · Orientação · Força · Resultados", C.BOLD + C.CYAN))
    print(cor(f"  Alfredo Ociola Francisco Romano · Luanda, Angola · {datetime.datetime.now().year}", C.DIM))
    print(cor(LINHA_LARGA, C.CYAN))
    print()

# ─────────────────────────────────────────────────────────────────────────────
# MENU PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────

def menu():
    opcoes = {
        "1": ("Auditoria Completa (todas as verificações automáticas + dorks)", None),
        "2": ("Verificação de Portas Expostas",                                 None),
        "3": ("Verificação SSL / TLS",                                          None),
        "4": ("Verificação Headers HTTP",                                       None),
        "5": ("Verificação DNS — SPF · DKIM · DMARC",                          None),
        "6": ("Inventário de Sub-Domínios",                                    None),
        "7": ("Listar todas as Dorks Shodan + Google",                          None),
        "8": ("Tabela de Resposta a Incidentes",                                None),
        "9": ("Glossário de Segurança",                                         None),
        "0": ("Sair",                                                           None),
    }

    while True:
        cabecalho()
        print(cor("  MENU PRINCIPAL", C.BOLD + C.WHITE))
        print()
        for k, (desc, _) in opcoes.items():
            cor_num  = C.CYAN if k != "0" else C.DIM
            print(f"    {cor(f'[{k}]', cor_num)}  {desc}")
        print()

        try:
            escolha = input(cor("  → Escolhe uma opção: ", C.BOLD)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            info("Saindo da auditoria AOFR TECH. Até à próxima!")
            sys.exit(0)

        resultados: list = []

        if escolha == "1":
            auditoria_subdomains(resultados)
            auditoria_portas(resultados)
            auditoria_ssl(resultados)
            auditoria_headers(resultados)
            auditoria_dns_email(resultados)
            imprimir_resumo_final(resultados)

        elif escolha == "2":
            auditoria_portas(resultados)
            imprimir_resumo_final(resultados)

        elif escolha == "3":
            auditoria_ssl(resultados)
            imprimir_resumo_final(resultados)

        elif escolha == "4":
            auditoria_headers(resultados)
            imprimir_resumo_final(resultados)

        elif escolha == "5":
            auditoria_dns_email(resultados)
            imprimir_resumo_final(resultados)

        elif escolha == "6":
            auditoria_subdomains(resultados)
            imprimir_resumo_final(resultados)

        elif escolha == "7":
            imprimir_dorks(resultados)

        elif escolha == "8":
            imprimir_tabela_resposta()

        elif escolha == "9":
            imprimir_glossario()

        elif escolha == "0":
            print()
            info("Saindo. Agenda a próxima auditoria: primeiro domingo do mês.")
            print()
            sys.exit(0)

        else:
            aviso("Opção inválida. Escolhe entre 0 e 9.")
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
    # Suporte a argumentos de linha de comando para uso não-interactivo
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        resultados: list = []

        if arg in ("--completa", "--full"):
            cabecalho()
            auditoria_subdomains(resultados)
            auditoria_portas(resultados)
            auditoria_ssl(resultados)
            auditoria_headers(resultados)
            auditoria_dns_email(resultados)
            imprimir_dorks(resultados)
            imprimir_resumo_final(resultados)

        elif arg == "--dorks":
            cabecalho()
            imprimir_dorks(resultados)

        elif arg == "--resposta":
            cabecalho()
            imprimir_tabela_resposta()

        elif arg == "--glossario":
            cabecalho()
            imprimir_glossario()

        elif arg in ("--help", "-h"):
            cabecalho()
            print("  USO:")
            print("    python3 aofr_tech_audit.py              → Menu interactivo")
            print("    python3 aofr_tech_audit.py --completa   → Auditoria completa automática")
            print("    python3 aofr_tech_audit.py --dorks      → Listar todas as dorks")
            print("    python3 aofr_tech_audit.py --resposta   → Tabela de resposta a incidentes")
            print("    python3 aofr_tech_audit.py --glossario  → Glossário de segurança")
            print()
        else:
            aviso(f"Argumento desconhecido: {arg}. Usa --help para ajuda.")
    else:
        menu()
