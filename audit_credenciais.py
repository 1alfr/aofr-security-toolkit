#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        AUDITORIA DE CREDENCIAIS PADRÃO - v2.0                   ║
║        Baseado no Manual de Credenciais Padrão (300 dispositivos)║
║        USO EXCLUSIVO PARA AUDITORES AUTORIZADOS                  ║
╚══════════════════════════════════════════════════════════════════╝

AVISO LEGAL: Este script destina-se EXCLUSIVAMENTE a auditores de
segurança certificados com autorização formal e escrita. O uso não
autorizado é crime (Angola Lei 7/17, CFAA EUA, NIS2 UE).

Metodologia: PTES / OWASP / NIST
"""

import sys
import os
import socket
import json
import csv
import time
import argparse
import ipaddress
import datetime
import threading
import queue
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Dependências opcionais ───────────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# ═══════════════════════════════════════════════════════════════════
# BASE DE CREDENCIAIS (extraída do Manual - 300 dispositivos)
# ═══════════════════════════════════════════════════════════════════

CREDENTIAL_DB = [
    # ── ROUTERS ────────────────────────────────────────────────────
    {"id": 1,  "fabricante": "Cisco IOS Router",       "usuario": "admin",         "senha": "admin",        "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 2,  "fabricante": "Cisco IOS Router",       "usuario": "cisco",         "senha": "cisco",        "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 3,  "fabricante": "Cisco Linksys E Series", "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 4,  "fabricante": "Cisco Linksys WRT54G",   "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 5,  "fabricante": "Cisco RV340/RV345",      "usuario": "cisco",         "senha": "cisco",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Router"},
    {"id": 6,  "fabricante": "TP-Link TL-WR840N",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 7,  "fabricante": "TP-Link Archer C7/C9",   "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 8,  "fabricante": "TP-Link TL-MR3420",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 9,  "fabricante": "Huawei HG8245/HG8546M",  "usuario": "root",          "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 10, "fabricante": "Huawei E5577 MiFi",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 11, "fabricante": "Huawei AR2200",           "usuario": "admin",         "senha": "Admin@123",    "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 12, "fabricante": "MikroTik RouterOS",       "usuario": "admin",         "senha": "",             "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 13, "fabricante": "MikroTik hAP ac2/hEX",   "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 14, "fabricante": "Netgear R6400/R7000",     "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 15, "fabricante": "Netgear Nighthawk AX12",  "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 16, "fabricante": "Netgear DGN2200",         "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 17, "fabricante": "D-Link DIR-300/600",      "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 18, "fabricante": "D-Link DIR-615",          "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 19, "fabricante": "D-Link DSL-2740R",        "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 20, "fabricante": "Asus RT-N12/RT-AC66U",    "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 21, "fabricante": "Asus RT-AX88U",           "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 22, "fabricante": "ZTE F609/F660 GPON",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 23, "fabricante": "ZTE ZXHN H108N",          "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 24, "fabricante": "Tenda AC10/AC15/F3",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 25, "fabricante": "Tenda N300/AC6",          "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 26, "fabricante": "Ubiquiti EdgeRouter",     "usuario": "ubnt",          "senha": "ubnt",         "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 27, "fabricante": "Ubiquiti UniFi Dream",    "usuario": "ui",            "senha": "ui",           "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 28, "fabricante": "Juniper JunOS SRX",       "usuario": "root",          "senha": "",             "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 29, "fabricante": "Juniper EX Series",       "usuario": "admin",         "senha": "admin123",     "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 30, "fabricante": "Belkin F7D1301/N600",     "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 31, "fabricante": "Allied Telesis AT-AR3050S","usuario": "manager",      "senha": "friend",       "protocolo": "Telnet","porta": 23,   "categoria": "Router"},
    {"id": 32, "fabricante": "3Com OfficeConnect",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 33, "fabricante": "Billion BiPAC 7800N",     "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 34, "fabricante": "Comtrend CT-536+",        "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 35, "fabricante": "AVM FRITZ!Box 7390",      "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 36, "fabricante": "AVM FRITZ!Box 7590",      "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 37, "fabricante": "Xiaomi Mi Router 3G",     "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 38, "fabricante": "Xiaomi Mi Router 4A",     "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 39, "fabricante": "GL.iNet GL-AR750S",       "usuario": "root",          "senha": "goodlife",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 40, "fabricante": "Mercusys MW305R/AC12",    "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 41, "fabricante": "Technicolor TG582n",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 42, "fabricante": "Sagem Fast 2504/2704",    "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 43, "fabricante": "Zyxel NBG6616/P-660HN",  "usuario": "admin",         "senha": "1234",         "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 44, "fabricante": "Zyxel VMG3625-T50B",     "usuario": "admin",         "senha": "1234",         "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 45, "fabricante": "Actiontec GT784WN",       "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 46, "fabricante": "Netis WF2419/WF2880",     "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 47, "fabricante": "Ruijie RG-EG Series",     "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},
    {"id": 48, "fabricante": "H3C MSR Series",          "usuario": "admin",         "senha": "admin",        "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 49, "fabricante": "Brocade ICX Series",      "usuario": "admin",         "senha": "password",     "protocolo": "SSH",   "porta": 22,   "categoria": "Router"},
    {"id": 50, "fabricante": "Sagemcom F@ST 5366",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Router"},

    # ── SWITCHES ───────────────────────────────────────────────────
    {"id": 51, "fabricante": "Cisco Catalyst 2960/3750","usuario": "admin",         "senha": "cisco",        "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 52, "fabricante": "Cisco Catalyst 9200/9300","usuario": "admin",         "senha": "cisco",        "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 53, "fabricante": "Cisco SG300/SG500",       "usuario": "cisco",         "senha": "cisco",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 54, "fabricante": "HP/Aruba ProCurve 2530",  "usuario": "admin",         "senha": "",             "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 55, "fabricante": "HP/Aruba 1910/1920S",     "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 56, "fabricante": "Netgear GS308/GS724T",    "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 57, "fabricante": "Netgear ProSAFE GS748T",  "usuario": "admin",         "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 58, "fabricante": "D-Link DGS-1210",         "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 59, "fabricante": "D-Link DGS-3120",         "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 60, "fabricante": "TP-Link TL-SG108E",       "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 61, "fabricante": "Huawei S5700/S6700",      "usuario": "admin",         "senha": "Admin@123",    "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 62, "fabricante": "Huawei S2750/S3700",      "usuario": "admin",         "senha": "Admin@123",    "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 63, "fabricante": "MikroTik CSS Series",     "usuario": "admin",         "senha": "",             "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 64, "fabricante": "Zyxel GS1900/GS2200",     "usuario": "admin",         "senha": "1234",         "protocolo": "HTTP",  "porta": 80,   "categoria": "Switch"},
    {"id": 65, "fabricante": "Extreme Summit X460",     "usuario": "admin",         "senha": "",             "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 66, "fabricante": "Allied Telesis AT-GS950",  "usuario": "manager",      "senha": "friend",       "protocolo": "Telnet","porta": 23,   "categoria": "Switch"},
    {"id": 67, "fabricante": "Ruijie RG-S5750",         "usuario": "admin",         "senha": "admin",        "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 68, "fabricante": "H3C S5120/S5500",         "usuario": "admin",         "senha": "admin",        "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 69, "fabricante": "Brocade FastIron",        "usuario": "admin",         "senha": "password",     "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},
    {"id": 70, "fabricante": "Ubiquiti UniFi Switch",   "usuario": "ubnt",          "senha": "ubnt",         "protocolo": "SSH",   "porta": 22,   "categoria": "Switch"},

    # ── CÂMERAS IP ─────────────────────────────────────────────────
    {"id": 71, "fabricante": "Hikvision DS-2CD",        "usuario": "admin",         "senha": "12345",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 72, "fabricante": "Hikvision DS-2DE PTZ",    "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 73, "fabricante": "Dahua IPC-HDW",           "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 74, "fabricante": "Dahua SD Series PTZ",     "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 75, "fabricante": "Axis P Series/Q Series",  "usuario": "root",          "senha": "pass",         "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 76, "fabricante": "Axis M2025-LE/P3245",     "usuario": "root",          "senha": "root",         "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 77, "fabricante": "Foscam FI9821P",          "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 88,   "categoria": "Camera IP"},
    {"id": 78, "fabricante": "Foscam C1/C2M",           "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 88,   "categoria": "Camera IP"},
    {"id": 79, "fabricante": "Amcrest IP8M",            "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 80, "fabricante": "Reolink RLC-410",         "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 81, "fabricante": "Vivotek FD8169A",         "usuario": "root",          "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 82, "fabricante": "Bosch Flexidome 7000i",   "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 83, "fabricante": "Sony SNC-EB600",          "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 84, "fabricante": "Panasonic WV-S Series",   "usuario": "admin",         "senha": "12345",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 85, "fabricante": "Hanwha QNV/XNV Series",   "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 86, "fabricante": "Uniview IPC Series",      "usuario": "admin",         "senha": "123456",       "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 87, "fabricante": "Tiandy TC-NC9300X3",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 88, "fabricante": "EZVIZ C3N/C6N",           "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 89, "fabricante": "Pelco Sarix IXE",         "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 90, "fabricante": "Grandstream GXV3611IR",   "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 91, "fabricante": "ACTi E21/E71",            "usuario": "admin",         "senha": "123456",       "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 92, "fabricante": "Geovision GV-BX",         "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 93, "fabricante": "Longse LBFE30ML500",      "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 94, "fabricante": "Imou Bullet/Dome",        "usuario": "admin",         "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},
    {"id": 95, "fabricante": "TP-Link Tapo C200/C310",  "usuario": "admin",         "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Camera IP"},

    # ── DVR/NVR ────────────────────────────────────────────────────
    {"id": 96,  "fabricante": "Hikvision DS-7200/7300 DVR","usuario": "admin",      "senha": "12345",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 97,  "fabricante": "Dahua XVR5108H/XVR5216H",   "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 98,  "fabricante": "Dahua NVR4108H/NVR4216H",   "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 99,  "fabricante": "Uniview NVR301 Series",      "usuario": "admin",      "senha": "123456",       "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 100, "fabricante": "Provision-ISR NVR-8200PX",   "usuario": "admin",      "senha": "1234",         "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 101, "fabricante": "QSee QT Series DVR",         "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 102, "fabricante": "Night Owl CL-DVR7",          "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 103, "fabricante": "Annke N48PAW NVR",           "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 104, "fabricante": "Zmodo ZM-SH75D4 DVR",       "usuario": "admin",      "senha": "111111",       "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 105, "fabricante": "Swann DVR-4575/NVR-8580",    "usuario": "admin",      "senha": "12345",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 106, "fabricante": "Lorex N862A82B NVR",         "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 107, "fabricante": "Genie CCTV NHDVR8-4K",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 108, "fabricante": "Tiandy TC-NR5020M7 NVR",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 109, "fabricante": "IDIS DR-2304P DVR",          "usuario": "admin",      "senha": "setup",        "protocolo": "HTTP",  "porta": 80,   "categoria": "DVR/NVR"},
    {"id": 110, "fabricante": "IndigoVision UltraView NVR", "usuario": "root",       "senha": "root",         "protocolo": "SSH",   "porta": 22,   "categoria": "DVR/NVR"},

    # ── IMPRESSORAS ────────────────────────────────────────────────
    {"id": 111, "fabricante": "HP LaserJet/OfficeJet",      "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 112, "fabricante": "HP JetDirect/LJ4250",        "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 113, "fabricante": "Canon imageRUNNER ADVANCE",  "usuario": "admin",      "senha": "canon",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 114, "fabricante": "Epson WorkForce Pro",        "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 115, "fabricante": "Xerox WorkCentre 7845",      "usuario": "admin",      "senha": "1111",         "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 116, "fabricante": "Xerox Phaser 3260/6510",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 117, "fabricante": "Ricoh Aficio MP Series",     "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 118, "fabricante": "Konica Minolta bizhub C224", "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 119, "fabricante": "Brother DCP/MFC Series",     "usuario": "admin",      "senha": "access",       "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 120, "fabricante": "Lexmark CS317dn/MS317dn",    "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 121, "fabricante": "Samsung ProXpress M Series", "usuario": "admin",      "senha": "sec00000",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 122, "fabricante": "Sharp MX Series",            "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 123, "fabricante": "OKI MC363dn/C332dn",         "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 124, "fabricante": "Kyocera ECOSYS M Series",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},
    {"id": 125, "fabricante": "Toshiba eSTUDIO Series",     "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Impressora"},

    # ── SERVIDORES ─────────────────────────────────────────────────
    {"id": 126, "fabricante": "Linux Ubuntu/Debian",        "usuario": "root",       "senha": "",             "protocolo": "SSH",   "porta": 22,   "categoria": "Servidor"},
    {"id": 127, "fabricante": "Linux CentOS/RHEL",          "usuario": "root",       "senha": "centos",       "protocolo": "SSH",   "porta": 22,   "categoria": "Servidor"},
    {"id": 128, "fabricante": "MySQL 5.x/8.x",              "usuario": "root",       "senha": "",             "protocolo": "TCP",   "porta": 3306, "categoria": "Servidor"},
    {"id": 129, "fabricante": "MySQL padrao antigo",        "usuario": "root",       "senha": "root",         "protocolo": "TCP",   "porta": 3306, "categoria": "Servidor"},
    {"id": 130, "fabricante": "PostgreSQL 9.x/14.x",        "usuario": "postgres",   "senha": "postgres",     "protocolo": "TCP",   "porta": 5432, "categoria": "Servidor"},
    {"id": 131, "fabricante": "MongoDB sem auth",           "usuario": "admin",      "senha": "",             "protocolo": "TCP",   "porta": 27017,"categoria": "Servidor"},
    {"id": 132, "fabricante": "Redis sem senha",            "usuario": "",           "senha": "",             "protocolo": "TCP",   "porta": 6379, "categoria": "Servidor"},
    {"id": 133, "fabricante": "Microsoft IIS 6.0",          "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Servidor"},
    {"id": 134, "fabricante": "Apache Tomcat 7/8/9",        "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 8080, "categoria": "Servidor"},
    {"id": 135, "fabricante": "Apache Tomcat manager",      "usuario": "tomcat",     "senha": "tomcat",       "protocolo": "HTTP",  "porta": 8080, "categoria": "Servidor"},
    {"id": 136, "fabricante": "VMware ESXi 6.x/7.x",       "usuario": "root",       "senha": "vmware",       "protocolo": "HTTPS", "porta": 443,  "categoria": "Servidor"},
    {"id": 137, "fabricante": "VMware vCenter Server",      "usuario": "administrator","senha": "vmware",     "protocolo": "HTTPS", "porta": 443,  "categoria": "Servidor"},
    {"id": 138, "fabricante": "Proxmox VE 6.x/7.x",        "usuario": "root",       "senha": "proxmox",      "protocolo": "HTTPS", "porta": 8006, "categoria": "Servidor"},
    {"id": 139, "fabricante": "Citrix XenServer",           "usuario": "root",       "senha": "xenroot",      "protocolo": "SSH",   "porta": 22,   "categoria": "Servidor"},
    {"id": 140, "fabricante": "Oracle DB Express/11g",      "usuario": "sys",        "senha": "change_on_install","protocolo":"TCP","porta": 1521, "categoria": "Servidor"},
    {"id": 141, "fabricante": "Oracle WebLogic Server",     "usuario": "weblogic",   "senha": "weblogic",     "protocolo": "HTTP",  "porta": 7001, "categoria": "Servidor"},
    {"id": 142, "fabricante": "IBM WebSphere",              "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 9060, "categoria": "Servidor"},
    {"id": 143, "fabricante": "Dell iDRAC 6/7/8",           "usuario": "root",       "senha": "calvin",       "protocolo": "HTTPS", "porta": 443,  "categoria": "Servidor"},
    {"id": 144, "fabricante": "HP iLO 3/4/5",               "usuario": "Administrator","senha": "",           "protocolo": "HTTPS", "porta": 443,  "categoria": "Servidor"},
    {"id": 145, "fabricante": "Supermicro IPMI/BMC",        "usuario": "admin",      "senha": "admin",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Servidor"},
    {"id": 146, "fabricante": "FTP vsftpd/ProFTPD",         "usuario": "ftp",        "senha": "ftp",          "protocolo": "FTP",   "porta": 21,   "categoria": "Servidor"},
    {"id": 147, "fabricante": "SNMP v1/v2 comunidade",      "usuario": "public",     "senha": "public",       "protocolo": "UDP",   "porta": 161,  "categoria": "Servidor"},
    {"id": 148, "fabricante": "SNMP comunidade escrita",    "usuario": "private",    "senha": "private",      "protocolo": "UDP",   "porta": 161,  "categoria": "Servidor"},
    {"id": 149, "fabricante": "Telnet generico",            "usuario": "admin",      "senha": "admin",        "protocolo": "Telnet","porta": 23,   "categoria": "Servidor"},
    {"id": 150, "fabricante": "Jenkins CI",                 "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 8080, "categoria": "Servidor"},
    {"id": 151, "fabricante": "GitLab CE",                  "usuario": "root",       "senha": "5iveL!fe",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Servidor"},
    {"id": 152, "fabricante": "Grafana padrao",             "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 3000, "categoria": "Servidor"},
    {"id": 153, "fabricante": "Kibana ELK Stack",           "usuario": "elastic",    "senha": "",             "protocolo": "HTTP",  "porta": 5601, "categoria": "Servidor"},
    {"id": 154, "fabricante": "Jupyter Notebook",           "usuario": "token",      "senha": "",             "protocolo": "HTTP",  "porta": 8888, "categoria": "Servidor"},
    {"id": 155, "fabricante": "phpMyAdmin",                 "usuario": "root",       "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Servidor"},
    {"id": 156, "fabricante": "Nagios XI",                  "usuario": "nagiosadmin","senha": "nagios",       "protocolo": "HTTP",  "porta": 80,   "categoria": "Servidor"},
    {"id": 157, "fabricante": "Zabbix padrao",              "usuario": "Admin",      "senha": "zabbix",       "protocolo": "HTTP",  "porta": 80,   "categoria": "Servidor"},
    {"id": 158, "fabricante": "Asterisk FreePBX",           "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Servidor"},
    {"id": 159, "fabricante": "OpenVPN Access Server",      "usuario": "openvpn",    "senha": "openvpn",      "protocolo": "HTTPS", "porta": 943,  "categoria": "Servidor"},
    {"id": 160, "fabricante": "Plex Media Server",          "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 32400,"categoria": "Servidor"},

    # ── FIREWALLS ──────────────────────────────────────────────────
    {"id": 161, "fabricante": "Cisco ASA 5505/5510",        "usuario": "admin",      "senha": "cisco",        "protocolo": "SSH",   "porta": 22,   "categoria": "Firewall"},
    {"id": 162, "fabricante": "Cisco Firepower FTD",        "usuario": "admin",      "senha": "Admin123",     "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 163, "fabricante": "Cisco PIX Firewall",         "usuario": "cisco",      "senha": "cisco",        "protocolo": "Telnet","porta": 23,   "categoria": "Firewall"},
    {"id": 164, "fabricante": "Fortinet FortiGate 60D",     "usuario": "admin",      "senha": "",             "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 165, "fabricante": "Fortinet FortiGate 200E",    "usuario": "admin",      "senha": "",             "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 166, "fabricante": "Palo Alto PA-220/PA-820",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 167, "fabricante": "Check Point Gaia R80",       "usuario": "admin",      "senha": "admin",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 168, "fabricante": "SonicWall TZ Series/NSA",    "usuario": "admin",      "senha": "password",     "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 169, "fabricante": "pfSense CE",                 "usuario": "admin",      "senha": "pfsense",      "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 170, "fabricante": "OPNsense",                   "usuario": "root",       "senha": "opnsense",     "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 171, "fabricante": "Sophos XG Firewall/UTM",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 172, "fabricante": "Juniper SSG NetScreen",      "usuario": "netscreen",  "senha": "netscreen",    "protocolo": "SSH",   "porta": 22,   "categoria": "Firewall"},
    {"id": 173, "fabricante": "Barracuda CloudGen",         "usuario": "admin",      "senha": "admin",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 174, "fabricante": "WatchGuard Firebox T",       "usuario": "admin",      "senha": "readwrite",    "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},
    {"id": 175, "fabricante": "Zyxel ZyWALL/USG",          "usuario": "admin",      "senha": "1234",         "protocolo": "HTTPS", "porta": 443,  "categoria": "Firewall"},

    # ── IoT ────────────────────────────────────────────────────────
    {"id": 176, "fabricante": "Philips Hue Bridge",         "usuario": "root",       "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 177, "fabricante": "Amazon Echo",                "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 178, "fabricante": "Google Nest Thermostat",     "usuario": "owner",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 179, "fabricante": "Samsung SmartThings Hub",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 180, "fabricante": "Shelly 1/Plug S",            "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 181, "fabricante": "Sonoff Basic/Mini/4CH",      "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 182, "fabricante": "Tuya Smart Plug/Switch",     "usuario": "tuya",       "senha": "tuya",         "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 183, "fabricante": "Wyze Cam v2/v3",             "usuario": "admin",      "senha": "admin",        "protocolo": "RTSP",  "porta": 554,  "categoria": "IoT"},
    {"id": 184, "fabricante": "Raspberry Pi Raspbian",      "usuario": "pi",         "senha": "raspberry",    "protocolo": "SSH",   "porta": 22,   "categoria": "IoT"},
    {"id": 185, "fabricante": "Arduino Yun/MKR WiFi",       "usuario": "root",       "senha": "arduino",      "protocolo": "SSH",   "porta": 22,   "categoria": "IoT"},
    {"id": 186, "fabricante": "ESP8266 NodeMCU/Wemos D1",   "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 187, "fabricante": "Xiaomi Mi Home",             "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 188, "fabricante": "TP-Link Kasa HS110",         "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 189, "fabricante": "Belkin WeMo Switch",         "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 190, "fabricante": "Ecobee SmartThermostat",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 191, "fabricante": "Ring Doorbell Pro",          "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 192, "fabricante": "Eufy Security Cam 2C",       "usuario": "admin",      "senha": "888888",       "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 193, "fabricante": "Tasmota Custom ESP",         "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "IoT"},
    {"id": 194, "fabricante": "Home Assistant HAOS",        "usuario": "homeassistant","senha": "",           "protocolo": "HTTP",  "porta": 8123, "categoria": "IoT"},
    {"id": 195, "fabricante": "Synology DiskStation NAS",   "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 5000, "categoria": "IoT"},

    # ── VoIP/PBX ───────────────────────────────────────────────────
    {"id": 196, "fabricante": "Cisco IP Phone 7900/8800",   "usuario": "admin",      "senha": "cisco",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 197, "fabricante": "Polycom VVX 300/400/500",    "usuario": "admin",      "senha": "456",          "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 198, "fabricante": "Grandstream GXP2135/2170",   "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 199, "fabricante": "Yealink T46S/T54W/T58A",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 200, "fabricante": "Snom D305/D715/D865",        "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 201, "fabricante": "Avaya IP Office 500",        "usuario": "Administrator","senha": "Administrator","protocolo":"HTTP", "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 202, "fabricante": "Mitel MiVoice 3300/250",     "usuario": "admin",      "senha": "admin",        "protocolo": "SSH",   "porta": 22,   "categoria": "VoIP/PBX"},
    {"id": 203, "fabricante": "Asterisk FreePBX 14/15/16",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 204, "fabricante": "3CX Phone System",           "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 205, "fabricante": "Sangoma FreePBX Distro",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 206, "fabricante": "Panasonic KX-TGP600",        "usuario": "admin",      "senha": "adminpass",    "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 207, "fabricante": "Fanvil X4/X6/X7C",          "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 208, "fabricante": "Htek UC902/UC926",           "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 209, "fabricante": "Cisco Unified CM",           "usuario": "admin",      "senha": "cisco",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},
    {"id": 210, "fabricante": "OpenSIPS 2.x/3.x",          "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "VoIP/PBX"},

    # ── SCADA/ICS ──────────────────────────────────────────────────
    {"id": 211, "fabricante": "Siemens S7-300/S7-400 PLC",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 212, "fabricante": "Siemens SIMATIC WinCC",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 213, "fabricante": "Rockwell MicroLogix",        "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 214, "fabricante": "Schneider Modicon M340",     "usuario": "USER",       "senha": "USER",         "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 215, "fabricante": "Schneider EcoStruxure",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 216, "fabricante": "GE MDS/Series 90 PLC",       "usuario": "admin",      "senha": "admin",        "protocolo": "Telnet","porta": 23,   "categoria": "SCADA/ICS"},
    {"id": 217, "fabricante": "ABB AC500 PLC",              "usuario": "admin",      "senha": "admin",        "protocolo": "FTP",   "porta": 21,   "categoria": "SCADA/ICS"},
    {"id": 218, "fabricante": "Honeywell Experion PKS",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 219, "fabricante": "Emerson DeltaV DCS",         "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 220, "fabricante": "Mitsubishi MELSEC iQ-R",     "usuario": "admin",      "senha": "",             "protocolo": "Telnet","porta": 23,   "categoria": "SCADA/ICS"},
    {"id": 221, "fabricante": "WAGO PFC200/750 Series",     "usuario": "admin",      "senha": "wago",         "protocolo": "FTP",   "porta": 21,   "categoria": "SCADA/ICS"},
    {"id": 222, "fabricante": "Phoenix Contact AXC F 2152", "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 223, "fabricante": "Moxa NPort 5210",            "usuario": "admin",      "senha": "moxa",         "protocolo": "Telnet","porta": 23,   "categoria": "SCADA/ICS"},
    {"id": 224, "fabricante": "Advantech WebAccess/SCADA",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "SCADA/ICS"},
    {"id": 225, "fabricante": "Inductive Automation Ignition","usuario": "admin",    "senha": "password",     "protocolo": "HTTP",  "porta": 8088, "categoria": "SCADA/ICS"},

    # ── ACCESS POINTS ──────────────────────────────────────────────
    {"id": 226, "fabricante": "Cisco Aironet 1200/1700",    "usuario": "admin",      "senha": "Cisco",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 227, "fabricante": "Cisco Meraki MR Series",     "usuario": "admin",      "senha": "cisco",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Access Point"},
    {"id": 228, "fabricante": "Ubiquiti UniFi AP AC",       "usuario": "ubnt",       "senha": "ubnt",         "protocolo": "SSH",   "porta": 22,   "categoria": "Access Point"},
    {"id": 229, "fabricante": "Ubiquiti airMAX M2/M5",      "usuario": "ubnt",       "senha": "ubnt",         "protocolo": "SSH",   "porta": 22,   "categoria": "Access Point"},
    {"id": 230, "fabricante": "Ruckus ZoneFlex/R710",       "usuario": "admin",      "senha": "sp-admin",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 231, "fabricante": "Aruba IAP 205/315/535",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 232, "fabricante": "TP-Link EAP245/EAP670 Omada","usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 233, "fabricante": "Netgear WAC104/WAX630",      "usuario": "admin",      "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 234, "fabricante": "Huawei AP6050DN/AP7060DN",   "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 235, "fabricante": "Cambium ePMP 1000/2000",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 236, "fabricante": "MikroTik RB411/wAP/cAP",     "usuario": "admin",      "senha": "",             "protocolo": "SSH",   "porta": 22,   "categoria": "Access Point"},
    {"id": 237, "fabricante": "Zyxel NWA50AX/NWA110AX",    "usuario": "admin",      "senha": "1234",         "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 238, "fabricante": "EnGenius ECW120/ECW230",     "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 239, "fabricante": "Linksys LAPAC2600/LAPN300",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},
    {"id": 240, "fabricante": "Tenda i21/i27",              "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Access Point"},

    # ── MODEMS/ONT ─────────────────────────────────────────────────
    {"id": 241, "fabricante": "Huawei HG8245H/HG8546M ONT", "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 242, "fabricante": "Huawei HG8310M/HG8120C ONT", "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 243, "fabricante": "ZTE F609/F660/F670L ONT",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 244, "fabricante": "ZTE F6640G GPON ONT",        "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 245, "fabricante": "Nokia G-010G-T/G-010G-P ONT","usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 246, "fabricante": "Fiberhome AN5506-04-F ONT",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 247, "fabricante": "Dasan H665/H660GW ONT",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 248, "fabricante": "Calix 716GE-I ONT",          "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 249, "fabricante": "Technicolor TC4400/DGA4132",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},
    {"id": 250, "fabricante": "Motorola SB6141/SBG6580",    "usuario": "admin",      "senha": "motorola",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Modem/ONT"},

    # ── NAS/STORAGE ────────────────────────────────────────────────
    {"id": 251, "fabricante": "Synology DS218/DS920+",      "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 5000, "categoria": "NAS/Storage"},
    {"id": 252, "fabricante": "QNAP TS-251+/TS-453Be",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 8080, "categoria": "NAS/Storage"},
    {"id": 253, "fabricante": "Western Digital MyCloud EX", "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "NAS/Storage"},
    {"id": 254, "fabricante": "Netgear ReadyNAS 526X",      "usuario": "admin",      "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "NAS/Storage"},
    {"id": 255, "fabricante": "Asustor AS6604T/AS7004T",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 8000, "categoria": "NAS/Storage"},
    {"id": 256, "fabricante": "TrueNAS Core/Scale",         "usuario": "root",       "senha": "abcd1234",     "protocolo": "HTTP",  "porta": 80,   "categoria": "NAS/Storage"},
    {"id": 257, "fabricante": "Buffalo LinkStation 500",    "usuario": "admin",      "senha": "password",     "protocolo": "HTTP",  "porta": 80,   "categoria": "NAS/Storage"},
    {"id": 258, "fabricante": "Drobo 5N2/B810n",            "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "NAS/Storage"},
    {"id": 259, "fabricante": "NetApp ONTAP 9.x",           "usuario": "admin",      "senha": "netapp1234",   "protocolo": "SSH",   "porta": 22,   "categoria": "NAS/Storage"},
    {"id": 260, "fabricante": "Dell/EMC VNX/Unity",         "usuario": "admin",      "senha": "Password123#", "protocolo": "HTTP",  "porta": 80,   "categoria": "NAS/Storage"},

    # ── PLATAFORMAS WEB ────────────────────────────────────────────
    {"id": 261, "fabricante": "WordPress",                  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Web/Painel"},
    {"id": 262, "fabricante": "Joomla 3.x/4.x",            "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Web/Painel"},
    {"id": 263, "fabricante": "Drupal 8.x/9.x",            "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Web/Painel"},
    {"id": 264, "fabricante": "cPanel WHM",                 "usuario": "root",       "senha": "padrao ISP",   "protocolo": "HTTPS", "porta": 2087, "categoria": "Web/Painel"},
    {"id": 265, "fabricante": "Plesk Onyx/Obsidian",        "usuario": "admin",      "senha": "setup",        "protocolo": "HTTPS", "porta": 8443, "categoria": "Web/Painel"},
    {"id": 266, "fabricante": "DirectAdmin",                "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 2222, "categoria": "Web/Painel"},
    {"id": 267, "fabricante": "Webmin",                     "usuario": "root",       "senha": "root",         "protocolo": "HTTPS", "porta": 10000,"categoria": "Web/Painel"},
    {"id": 268, "fabricante": "Magento 2.x",                "usuario": "admin",      "senha": "admin123",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Web/Painel"},
    {"id": 269, "fabricante": "OpenCart",                   "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Web/Painel"},
    {"id": 270, "fabricante": "WHMCS",                      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Web/Painel"},

    # ── DISPOSITIVOS DIVERSOS ──────────────────────────────────────
    {"id": 271, "fabricante": "Android ADB debug",          "usuario": "root",       "senha": "",             "protocolo": "ADB",   "porta": 5555, "categoria": "Dispositivos"},
    {"id": 272, "fabricante": "Apple iOS jailbreak SSH",     "usuario": "mobile",     "senha": "alpine",       "protocolo": "SSH",   "porta": 22,   "categoria": "Dispositivos"},
    {"id": 273, "fabricante": "Samsung Admin mode",         "usuario": "admin",      "senha": "samsung",      "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 274, "fabricante": "Zoom ZVC Series Video",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 275, "fabricante": "Polycom RealPresence 500",   "usuario": "admin",      "senha": "456",          "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 276, "fabricante": "Cisco TelePresence SX10",    "usuario": "admin",      "senha": "TANDBERG",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 277, "fabricante": "Crestron DM NVX/MC3",        "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 278, "fabricante": "AMX NMX-ENC-N2212 AV",      "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 279, "fabricante": "Lantronix SCS48/EDS32PR",    "usuario": "admin",      "senha": "admin",        "protocolo": "Telnet","porta": 23,   "categoria": "Dispositivos"},
    {"id": 280, "fabricante": "Digi CM 48/ConnectPort",     "usuario": "root",       "senha": "dbps",         "protocolo": "Telnet","porta": 23,   "categoria": "Dispositivos"},
    {"id": 281, "fabricante": "Hikvision Intercom DS-KH6320","usuario": "admin",     "senha": "12345",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 282, "fabricante": "2N Helios IP Video Kit",     "usuario": "admin",      "senha": "2n",           "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 283, "fabricante": "Bosch DCN Conference",       "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 284, "fabricante": "Motorola AP-7181/AP-7161",   "usuario": "admin",      "senha": "motorola",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 285, "fabricante": "Zebra TC70/TC75 Scanner",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 286, "fabricante": "Honeywell CT60/CN80 Scanner","usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 287, "fabricante": "Epson TM-T88 Receipt",       "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 288, "fabricante": "Verifone MX915/P400 POS",    "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 289, "fabricante": "Ingenico iSC480/iSMP4 POS",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 290, "fabricante": "PAX A920/A80 POS Terminal",  "usuario": "admin",      "senha": "pax9999",      "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 291, "fabricante": "Teltonika RUT955/RUT240 4G", "usuario": "admin",      "senha": "admin01",      "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 292, "fabricante": "Cradlepoint IBR900/AER2200", "usuario": "admin",      "senha": "$(serial)",    "protocolo": "HTTPS", "porta": 443,  "categoria": "Dispositivos"},
    {"id": 293, "fabricante": "Sierra Wireless RV55/RV50X", "usuario": "user",       "senha": "12345",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 294, "fabricante": "Peplink Balance 20X/MAX BR1","usuario": "admin",      "senha": "admin",        "protocolo": "HTTPS", "porta": 443,  "categoria": "Dispositivos"},
    {"id": 295, "fabricante": "Netgear ReadyNAS Duo RND2000","usuario": "admin",     "senha": "infrant1",     "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 296, "fabricante": "Datalogic Memor 10/Skorpio", "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 297, "fabricante": "Bixolon SRP-Q300 Receipt",   "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 298, "fabricante": "Star Micronics TSP143IIIU",  "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 299, "fabricante": "Intermec CK70/CK71 Scanner", "usuario": "admin",      "senha": "admin",        "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
    {"id": 300, "fabricante": "OKI MC363dn receipt/label",  "usuario": "admin",      "senha": "",             "protocolo": "HTTP",  "porta": 80,   "categoria": "Dispositivos"},
]

# ═══════════════════════════════════════════════════════════════════
# CLASSES DE DADOS
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ResultadoTeste:
    ip: str
    porta: int
    protocolo: str
    fabricante: str
    usuario: str
    senha: str
    categoria: str
    status: str       # "VULNERAVEL" | "SEGURO" | "OFFLINE" | "ERRO"
    detalhe: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())


# ═══════════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES
# ═══════════════════════════════════════════════════════════════════

VERDE  = "\033[92m"
VERMELHO = "\033[91m"
AMARELO = "\033[93m"
AZUL   = "\033[94m"
CINZA  = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""{AZUL}{BOLD}
╔══════════════════════════════════════════════════════════════════╗
║    AUDITORIA DE CREDENCIAIS PADRÃO  v2.0  [300 dispositivos]    ║
║    Manual de Credenciais Padrão  |  PTES/OWASP/NIST             ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠  USO EXCLUSIVO PARA AUDITORES AUTORIZADOS                    ║
║  ⚠  Obtenha autorização formal antes de qualquer teste          ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")

def autorizar():
    """Gate de autorização obrigatório."""
    print(f"{AMARELO}╔══════════════════════════════════════════════════════════════╗")
    print(f"║  DECLARAÇÃO DE AUTORIZAÇÃO OBRIGATÓRIA                       ║")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Confirmo que:                                               ║")
    print(f"║   [1] Sou auditor de segurança com mandato formal e escrito  ║")
    print(f"║   [2] Tenho autorização expressa do proprietário da rede     ║")
    print(f"║   [3] Compreendo que o uso não autorizado é crime            ║")
    print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")
    resp = input("\nDigite 'AUTORIZO' para continuar: ").strip()
    if resp != "AUTORIZO":
        print(f"{VERMELHO}[!] Sem autorização confirmada. A encerrar.{RESET}")
        sys.exit(1)
    print(f"{VERDE}[✓] Autorização confirmada. Auditoria iniciada.\n{RESET}")


def porta_aberta(ip: str, porta: int, timeout: float = 1.5) -> bool:
    """Verifica se uma porta TCP está aberta."""
    try:
        with socket.create_connection((ip, porta), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def testar_http(ip: str, porta: int, usuario: str, senha: str,
                protocolo: str = "HTTP", timeout: int = 5) -> tuple[str, str]:
    """Testa credenciais HTTP/HTTPS básico."""
    if not HAS_REQUESTS:
        return "ERRO", "requests não instalado"
    scheme = "https" if protocolo == "HTTPS" or porta in (443, 8443, 8006) else "http"
    url = f"{scheme}://{ip}:{porta}/"
    try:
        r = requests.get(url, auth=(usuario, senha), timeout=timeout,
                         verify=False, allow_redirects=True)
        if r.status_code in (200, 201, 301, 302):
            return "VULNERAVEL", f"HTTP {r.status_code}"
        elif r.status_code == 401:
            return "SEGURO", "Autenticação rejeitada (401)"
        elif r.status_code == 403:
            return "SEGURO", "Acesso negado (403)"
        else:
            return "ERRO", f"HTTP {r.status_code}"
    except requests.exceptions.SSLError:
        return "ERRO", "Erro SSL"
    except requests.exceptions.ConnectionError:
        return "OFFLINE", "Sem ligação"
    except requests.exceptions.Timeout:
        return "OFFLINE", "Timeout"
    except Exception as e:
        return "ERRO", str(e)[:60]


def testar_ssh(ip: str, porta: int, usuario: str, senha: str,
               timeout: int = 5) -> tuple[str, str]:
    """Testa credenciais SSH com Paramiko."""
    if not HAS_PARAMIKO:
        return "ERRO", "paramiko não instalado"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port=porta, username=usuario, password=senha,
                    timeout=timeout, banner_timeout=timeout,
                    auth_timeout=timeout, look_for_keys=False,
                    allow_agent=False)
        ssh.close()
        return "VULNERAVEL", "SSH login bem-sucedido"
    except paramiko.AuthenticationException:
        return "SEGURO", "Autenticação SSH rejeitada"
    except paramiko.ssh_exception.NoValidConnectionsError:
        return "OFFLINE", "Sem ligação SSH"
    except socket.timeout:
        return "OFFLINE", "Timeout SSH"
    except Exception as e:
        return "ERRO", str(e)[:60]


def testar_tcp_porta(ip: str, porta: int, timeout: float = 2.0) -> tuple[str, str]:
    """Verifica presença de serviço TCP (MongoDB, Redis, etc.)."""
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner_bytes = s.recv(256)
                banner_txt = banner_bytes.decode("utf-8", errors="ignore").strip()
                return "VULNERAVEL", f"Porta aberta sem auth | banner: {banner_txt[:40]}"
            except socket.timeout:
                return "VULNERAVEL", "Porta aberta (serviço responde)"
    except (ConnectionRefusedError, socket.timeout, OSError):
        return "OFFLINE", "Porta fechada/filtrada"


# ═══════════════════════════════════════════════════════════════════
# MOTOR DE AUDITORIA
# ═══════════════════════════════════════════════════════════════════

def auditar_alvo(ip: str, cred: dict, timeout: int = 5) -> ResultadoTeste:
    """Executa teste de uma credencial num IP específico."""
    protocolo  = cred["protocolo"]
    porta      = cred["porta"]
    usuario    = cred["usuario"]
    senha      = cred["senha"]
    fabricante = cred["fabricante"]
    categoria  = cred["categoria"]

    # Primeiro verifica conectividade
    if not porta_aberta(ip, porta, timeout=1.5):
        return ResultadoTeste(ip, porta, protocolo, fabricante,
                              usuario, senha, categoria,
                              "OFFLINE", "Porta fechada/filtrada")

    # Testa segundo protocolo
    if protocolo in ("HTTP", "HTTPS"):
        status, detalhe = testar_http(ip, porta, usuario, senha, protocolo, timeout)
    elif protocolo == "SSH":
        status, detalhe = testar_ssh(ip, porta, usuario, senha, timeout)
    elif protocolo in ("TCP", "MongoDB", "Redis", "MySQL", "PSQL"):
        status, detalhe = testar_tcp_porta(ip, porta, timeout)
    elif protocolo == "Telnet":
        status, detalhe = testar_tcp_porta(ip, porta, timeout)
    else:
        status, detalhe = "ERRO", f"Protocolo '{protocolo}' não suportado"

    return ResultadoTeste(ip, porta, protocolo, fabricante,
                          usuario, senha, categoria, status, detalhe)


def auditar_rede(alvos: list[str], categorias: list[str] = None,
                 threads: int = 20, timeout: int = 5,
                 verbose: bool = False) -> list[ResultadoTeste]:
    """Audita uma lista de IPs contra a base de credenciais."""

    db_filtrada = CREDENTIAL_DB
    if categorias:
        cats_lower = [c.lower() for c in categorias]
        db_filtrada = [c for c in CREDENTIAL_DB
                       if c["categoria"].lower() in cats_lower]

    total_testes = len(alvos) * len(db_filtrada)
    print(f"{AZUL}[*] Alvos: {len(alvos)} IPs  |  Credenciais: {len(db_filtrada)}  "
          f"|  Testes: {total_testes}  |  Threads: {threads}{RESET}\n")

    resultados = []
    concluidos = 0
    lock = threading.Lock()

    tarefas = [(ip, cred) for ip in alvos for cred in db_filtrada]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futuros = {
            executor.submit(auditar_alvo, ip, cred, timeout): (ip, cred)
            for ip, cred in tarefas
        }
        for futuro in as_completed(futuros):
            res: ResultadoTeste = futuro.result()
            with lock:
                resultados.append(res)
                concluidos += 1
                pct = (concluidos / total_testes) * 100

                if res.status == "VULNERAVEL":
                    cor = VERDE
                    sym = "✘ VULNERÁVEL"
                elif res.status == "SEGURO":
                    cor = CINZA
                    sym = "✓ SEGURO   "
                elif res.status == "OFFLINE":
                    cor = AMARELO
                    sym = "~ OFFLINE  "
                else:
                    cor = VERMELHO
                    sym = "? ERRO     "

                if res.status == "VULNERAVEL" or verbose:
                    print(f"{cor}[{sym}] {res.ip}:{res.porta} | "
                          f"{res.fabricante} | {res.usuario}:{res.senha or '(vazio)'} "
                          f"| {res.detalhe}{RESET}")

                if concluidos % 50 == 0 or concluidos == total_testes:
                    print(f"{CINZA}  → Progresso: {concluidos}/{total_testes} ({pct:.1f}%){RESET}")

    return resultados


# ═══════════════════════════════════════════════════════════════════
# RELATÓRIO
# ═══════════════════════════════════════════════════════════════════

def gerar_relatorio(resultados: list[ResultadoTeste], saida_dir: str = "."):
    """Gera relatório JSON, CSV e sumário TXT."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(saida_dir, exist_ok=True)

    vulneraveis = [r for r in resultados if r.status == "VULNERAVEL"]
    seguros     = [r for r in resultados if r.status == "SEGURO"]
    offline     = [r for r in resultados if r.status == "OFFLINE"]
    erros       = [r for r in resultados if r.status == "ERRO"]

    # ── JSON completo ─────────────────────────────────────────────
    json_path = os.path.join(saida_dir, f"auditoria_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([vars(r) for r in resultados], f, indent=2, ensure_ascii=False)

    # ── CSV vulneráveis ───────────────────────────────────────────
    csv_path = os.path.join(saida_dir, f"vulneraveis_{ts}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "porta", "protocolo",
                                               "fabricante", "usuario", "senha",
                                               "categoria", "detalhe", "timestamp"])
        writer.writeheader()
        writer.writerows([vars(r) for r in vulneraveis])

    # ── Sumário TXT ───────────────────────────────────────────────
    txt_path = os.path.join(saida_dir, f"sumario_{ts}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  RELATÓRIO DE AUDITORIA DE CREDENCIAIS PADRÃO\n")
        f.write(f"  Gerado em: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"  TOTAL DE TESTES : {len(resultados)}\n")
        f.write(f"  VULNERÁVEIS     : {len(vulneraveis)}\n")
        f.write(f"  SEGUROS         : {len(seguros)}\n")
        f.write(f"  OFFLINE         : {len(offline)}\n")
        f.write(f"  ERROS           : {len(erros)}\n\n")

        if vulneraveis:
            f.write("─" * 70 + "\n")
            f.write("  DISPOSITIVOS VULNERÁVEIS\n")
            f.write("─" * 70 + "\n")
            for r in sorted(vulneraveis, key=lambda x: (x.ip, x.porta)):
                f.write(f"\n  IP       : {r.ip}:{r.porta}\n")
                f.write(f"  Fabricante: {r.fabricante}\n")
                f.write(f"  Categoria : {r.categoria}\n")
                f.write(f"  Credencial: {r.usuario} / {r.senha or '(sem senha)'}\n")
                f.write(f"  Protocolo : {r.protocolo}\n")
                f.write(f"  Detalhe   : {r.detalhe}\n")
                f.write(f"  Timestamp : {r.timestamp}\n")

        # Distribuição por categoria
        f.write("\n" + "─" * 70 + "\n")
        f.write("  DISTRIBUIÇÃO POR CATEGORIA\n")
        f.write("─" * 70 + "\n")
        cats: dict[str, int] = {}
        for r in vulneraveis:
            cats[r.categoria] = cats.get(r.categoria, 0) + 1
        for cat, n in sorted(cats.items(), key=lambda x: -x[1]):
            f.write(f"  {cat:<25} {n} vulnerável(is)\n")

        f.write("\n" + "─" * 70 + "\n")
        f.write("  RECOMENDAÇÕES IMEDIATAS\n")
        f.write("─" * 70 + "\n")
        f.write("  1. Alterar TODAS as credenciais padrão identificadas\n")
        f.write("  2. Desativar protocolos inseguros (Telnet, HTTP, SNMPv1/v2)\n")
        f.write("  3. Ativar MFA em todos os sistemas críticos\n")
        f.write("  4. Segmentar redes IoT e SCADA em VLANs separadas\n")
        f.write("  5. Atualizar firmware de todos os dispositivos\n")

    # ── Sumário no terminal ───────────────────────────────────────
    print(f"\n{BOLD}{'═'*60}")
    print(f"  SUMÁRIO DA AUDITORIA")
    print(f"{'═'*60}{RESET}")
    print(f"  {BOLD}Total de testes :{RESET}  {len(resultados)}")
    print(f"  {VERMELHO}{BOLD}Vulneráveis     :{RESET}  {len(vulneraveis)}")
    print(f"  {VERDE}Seguros         :{RESET}  {len(seguros)}")
    print(f"  {AMARELO}Offline         :{RESET}  {len(offline)}")
    print(f"  {CINZA}Erros           :{RESET}  {len(erros)}")
    print(f"\n  Relatórios guardados em: {saida_dir}/")
    print(f"  ├─ {os.path.basename(json_path)}")
    print(f"  ├─ {os.path.basename(csv_path)}")
    print(f"  └─ {os.path.basename(txt_path)}")
    print(f"{BOLD}{'═'*60}{RESET}\n")

    return json_path, csv_path, txt_path


# ═══════════════════════════════════════════════════════════════════
# FUNÇÕES UTILITÁRIAS
# ═══════════════════════════════════════════════════════════════════

def expandir_alvos(alvos_str: list[str]) -> list[str]:
    """Expande IPs, ranges CIDR e listas de ficheiros."""
    ips = []
    for alvo in alvos_str:
        if os.path.isfile(alvo):
            with open(alvo) as f:
                for linha in f:
                    linha = linha.strip()
                    if linha and not linha.startswith("#"):
                        ips.extend(expandir_alvos([linha]))
        else:
            try:
                rede = ipaddress.ip_network(alvo, strict=False)
                ips.extend([str(ip) for ip in rede.hosts()])
            except ValueError:
                ips.append(alvo)
    return list(dict.fromkeys(ips))  # deduplica preservando ordem


def listar_categorias():
    cats = sorted(set(c["categoria"] for c in CREDENTIAL_DB))
    print(f"\n{BOLD}Categorias disponíveis ({len(cats)}):{RESET}")
    for cat in cats:
        n = sum(1 for c in CREDENTIAL_DB if c["categoria"] == cat)
        print(f"  {AZUL}·{RESET} {cat:<25} ({n} credenciais)")
    print()


def listar_fabricante(fabricante: str):
    resultados = [c for c in CREDENTIAL_DB
                  if fabricante.lower() in c["fabricante"].lower()]
    if not resultados:
        print(f"{AMARELO}Nenhum resultado para '{fabricante}'{RESET}")
        return
    print(f"\n{BOLD}Resultados para '{fabricante}':{RESET}")
    for c in resultados:
        print(f"  [{c['id']:>3}] {c['fabricante']:<40} "
              f"{c['usuario']:<20} {c['senha'] or '(vazio)':<20} "
              f"{c['protocolo']}:{c['porta']}")
    print()


def verificar_dependencias():
    status = []
    status.append(f"  requests  : {'✓ instalado' if HAS_REQUESTS  else '✗ pip install requests'}")
    status.append(f"  paramiko  : {'✓ instalado' if HAS_PARAMIKO  else '✗ pip install paramiko'}")
    print(f"\n{BOLD}Dependências:{RESET}")
    for s in status:
        print(f"  {s}")
    print()


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def cli():
    parser = argparse.ArgumentParser(
        description="Auditoria de Credenciais Padrão — 300 Dispositivos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXEMPLOS:
  # Auditar host único
  python audit_credenciais.py -a 192.168.1.1

  # Auditar sub-rede completa
  python audit_credenciais.py -a 192.168.1.0/24

  # Apenas routers e switches
  python audit_credenciais.py -a 10.0.0.0/24 -c Router Switch

  # Lista de IPs em ficheiro
  python audit_credenciais.py -a alvos.txt --threads 50

  # Pesquisar credenciais por fabricante
  python audit_credenciais.py --fabricante Hikvision

  # Listar todas as categorias
  python audit_credenciais.py --categorias

  # Ver dependências
  python audit_credenciais.py --deps
"""
    )
    parser.add_argument("-a", "--alvos", nargs="+",
                        help="IPs, CIDRs ou ficheiro com alvos")
    parser.add_argument("-c", "--categorias", nargs="+",
                        help="Filtrar por categoria(s)")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="Nº de threads paralelas (padrão: 20)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Timeout por ligação em segundos (padrão: 5)")
    parser.add_argument("-o", "--output", default="relatorios",
                        help="Diretório de saída dos relatórios")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Mostrar todos os resultados (não só vulneráveis)")
    parser.add_argument("--fabricante", metavar="NOME",
                        help="Pesquisar credenciais por fabricante")
    parser.add_argument("--listar-categorias", action="store_true",
                        help="Listar categorias disponíveis")
    parser.add_argument("--deps", action="store_true",
                        help="Verificar dependências instaladas")
    parser.add_argument("--sem-confirmacao", action="store_true",
                        help="Saltar confirmação de autorização (CI/automação)")

    args = parser.parse_args()

    banner()

    if args.listar_categorias:
        listar_categorias()
        return

    if args.fabricante:
        listar_fabricante(args.fabricante)
        return

    if args.deps:
        verificar_dependencias()
        return

    if not args.alvos:
        parser.print_help()
        return

    if not args.sem_confirmacao:
        autorizar()

    alvos = expandir_alvos(args.alvos)
    if not alvos:
        print(f"{VERMELHO}[!] Nenhum alvo válido encontrado.{RESET}")
        sys.exit(1)

    print(f"{AZUL}[*] {len(alvos)} alvos expandidos{RESET}")

    inicio = time.time()
    resultados = auditar_rede(
        alvos=alvos,
        categorias=args.categorias,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    duracao = time.time() - inicio

    print(f"\n{CINZA}[*] Duração total: {duracao:.1f}s{RESET}")
    gerar_relatorio(resultados, saida_dir=args.output)


# ═══════════════════════════════════════════════════════════════════
# MODO INTERATIVO RÁPIDO (sem argparse)
# ═══════════════════════════════════════════════════════════════════

def modo_interativo():
    """Interface simples para uso direto sem argumentos CLI."""
    banner()
    autorizar()

    print("Introduza o(s) alvo(s) separados por vírgula (IP, CIDR ou ficheiro):")
    entrada = input("  Alvo(s): ").strip()
    alvos = expandir_alvos([a.strip() for a in entrada.split(",")])

    print("\nFiltrar por categoria? (Enter para todas):")
    listar_categorias()
    cats_entrada = input("  Categorias (ex: Router Switch): ").strip()
    categorias = cats_entrada.split() if cats_entrada else None

    resultados = auditar_rede(alvos=alvos, categorias=categorias,
                              threads=20, timeout=5, verbose=False)
    gerar_relatorio(resultados)


# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        modo_interativo()
