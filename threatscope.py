#!/usr/bin/env python3
r"""
ThreatScope — a live cyber-attack map for your terminal.

A dotted world map with attack arcs flying between countries, impact ripples,
a live attack feed, and panels for most-attacked countries, attack types and
targets. Python standard library only; works on Windows, macOS and Linux.

DATA SOURCES
  (default)    Simulated attacks. Nothing real — good for a screensaver.

  --radar      REAL data from Cloudflare Radar: which countries attack which,
               the attack-type mix and the most attacked / attacking
               countries, from all HTTP attack traffic Cloudflare blocked over
               the last 24 hours. Refreshed every 5 minutes. Radar publishes
               shares, not individual events, so arcs are sampled from those
               real proportions. Needs a free Cloudflare API token with the
               "Radar: Read" permission:
                 PowerShell:  $env:CLOUDFLARE_API_TOKEN="<token>"
                 bash:        export CLOUDFLARE_API_TOKEN=<token>

  --log FILE   LIVE attacks against your own machine, as they happen. Tails
               a Windows Firewall log (pfirewall.log), an nginx/Apache access
               log, or an SSH auth / fail2ban log; every blocked connection,
               exploit probe or failed login becomes an arc from the
               attacker's country to you. Attacker IPs are geolocated with
               the free ip-api.com service.

  --feed FILE  Your own events, one JSON object per line (tailed live):
               {"src": "CN", "dst": "US", "type": "malware",
                "name": "AgentTesla", "industry": "Healthcare"}
               src/dst: ISO country code or {"lat":..,"lon":..,"name":..}.

EXAMPLES
  python threatscope.py
  python threatscope.py --radar
  python threatscope.py --log C:\Windows\System32\LogFiles\Firewall\pfirewall.log
  python3 threatscope.py --log /var/log/nginx/access.log

KEYS  q quit · p pause · + / - arc rate · 1 2 3 toggle attack types ·
      m dotted/solid map · c clear stats
"""

import argparse
import collections
try:
    import curses
except ImportError:          # e.g. stock Python on Windows
    curses = None
import ipaddress
import json
import locale
import math
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# --------------------------------------------------------------------------
# World geometry — simplified coastlines as (lon, lat) polygons.
# Hand-plotted at roughly 1–3° resolution; plenty for a terminal.
# --------------------------------------------------------------------------

LAND = [
    # North America
    [(-168,66),(-162,70),(-156,71.3),(-141,69.6),(-128,70),(-115,68.5),(-95,72),
     (-82,73),(-80,63),(-94,58.7),(-92,57),(-82,52.5),(-79,54.5),(-77,60),(-70,61),
     (-64,60),(-61,56),(-56,52),(-60,48),(-64,49.5),(-66,45),(-70,43.5),(-70,41.5),
     (-74,40.5),(-76,37),(-75.5,35.3),(-79,33),(-81,31),(-80,26),(-80.5,25),(-82,26.5),
     (-83,29),(-85,30),(-89,30.2),(-94,29.6),(-97,27.5),(-97.5,24),(-97.5,21.5),(-96,19),
     (-94.5,18.2),(-91,18.5),(-90.5,21),(-87,21.5),(-88,17.5),(-88.5,16),(-84,15.5),
     (-83.5,11),(-81.5,9),(-79.5,9.5),(-77.5,8.5),(-78.5,7.5),(-80,7.5),(-83,8.3),
     (-85.7,10),(-87.5,13),(-91.5,14),(-94.5,16),(-97,15.8),(-101,17.5),(-105.5,20),
     (-105.5,22.5),(-109,26),(-112.5,29.5),(-114.7,31.5),(-114,30),(-112,27),(-110,24),
     (-110,23),(-112,25),(-114,27.5),(-115.5,30),(-117,32.5),(-118.5,34),(-120.6,34.6),
     (-122.5,37.5),(-124,40.5),(-124.5,43),(-124,46),(-124.7,48.4),(-123,49),(-127,50.5),
     (-130,54.5),(-133,57.5),(-137,59),(-140,59.8),(-146,60.5),(-151,59.5),(-152,58),
     (-157,57),(-162,55),(-164,55),(-158,58),(-162,58.7),(-164.5,60.5),(-165,62.5),
     (-161,64.5),(-166,64.6)],
    # Greenland
    [(-73,78),(-60,82),(-35,83.5),(-20,82),(-18,77),(-21,72),(-22,70),(-32,68),(-40,65),
     (-43,60),(-48,61),(-52,65),(-54,68),(-55,71),(-60,76)],
    # Canadian Arctic islands
    [(-80,73.5),(-68,70.5),(-62,66.5),(-66,62),(-73,63),(-78,64),(-90,69)],
    [(-120,77),(-95,81.5),(-62,82.8),(-75,78),(-90,76),(-100,74),(-120,73),(-125,75)],
    [(-118,70),(-102,68.5),(-100,72),(-112,73),(-118,72)],
    # Caribbean
    [(-85,21.8),(-80,23.1),(-74.2,20.2),(-77.5,19.9),(-80,21.7)],
    [(-74.4,19.8),(-70,19.8),(-68.4,18.6),(-71.5,17.6),(-74.4,18.4)],
    # South America
    [(-77.5,8.5),(-75.5,10.8),(-72,12.3),(-71.5,10.5),(-68,10.6),(-62,10.7),(-60,8.5),
     (-57,6),(-52,5),(-50,1.5),(-50,-0.5),(-44,-2.5),(-39,-3.5),(-35,-5.5),(-35,-9),
     (-37,-12),(-39,-14),(-39.5,-18),(-40.5,-21.5),(-42,-23),(-45,-23.8),(-48.5,-26),
     (-48.7,-28.5),(-51,-31),(-53.5,-34),(-58,-34.5),(-57,-36.5),(-58,-38.5),(-62,-39),
     (-62.3,-41),(-65,-41),(-64,-42.5),(-65.5,-45),(-67.5,-46.5),(-66,-48),(-69,-51.5),
     (-68.5,-52.5),(-70,-53),(-71.5,-53.8),(-74.5,-52),(-75.5,-48),(-74,-44),(-73.5,-40),
     (-73.5,-37),(-71.5,-32),(-71.3,-28),(-70.5,-23),(-70.2,-18.5),(-75,-15.5),(-76.5,-13),
     (-79.5,-7.5),(-81.2,-5.5),(-80,-2.5),(-80.5,-0.5),(-79.5,1),(-78.8,1.5),(-77.5,4),
     (-77.3,7)],
    [(-68.6,-52.6),(-65,-55),(-70,-55),(-74,-53)],
    # Africa
    [(-17,21),(-16.5,24),(-15,27.5),(-12,29),(-9.8,30.5),(-9.5,32.5),(-6.5,35.7),(-2,35.2),
     (3,36.8),(10,37.3),(11,35),(10,33.6),(15.2,32.3),(19,30.3),(20,32),(25,31.8),(29,30.9),
     (32.3,31.2),(34.2,31.2),(34.9,29.5),(33.5,27.8),(35.5,23.5),(37.2,21),(38.8,17.5),
     (43.3,12.6),(44,11),(51.2,11.8),(51,10.5),(49.5,6.5),(47.5,4),(41.5,-1.5),(39.5,-5),
     (39.3,-8.5),(40.5,-10.5),(40.5,-15),(35,-20),(35.5,-24),(32.8,-26),(32.5,-28.6),
     (30,-31.3),(27,-33.8),(22,-34),(20,-34.8),(18.4,-34),(17.8,-32.5),(15,-27),(14.5,-23),
     (11.8,-17.2),(12.3,-13),(13.5,-11),(13,-8),(12,-5),(9.4,-1),(9.7,3),(8.5,4.5),(6,4.3),
     (4.5,6.3),(1.5,6),(-2,4.7),(-7.5,4.4),(-11,6.8),(-13,8),(-15,11),(-16.7,12.5),
     (-17.5,14.7),(-16.5,16.5),(-16,19)],
    [(49.3,-12),(50.5,-15.5),(49.5,-17.5),(47,-25),(45,-25.5),(43.5,-21.5),(44.3,-16.5),
     (46.5,-15.5)],
    # Eurasia
    [(-9.5,37),(-8.8,42.5),(-9.3,43.2),(-1.5,43.4),(-1.3,46),(-4.5,48),(-1.5,48.6),
     (1.5,50.1),(4,51.4),(8,53.5),(8.5,57),(10.5,57.7),(10.5,54.5),(14,54),(19,54.4),
     (21,56.5),(21.5,57.3),(24,57.2),(23.5,58.8),(28,59.5),(22.5,60.2),(21.5,61.5),
     (21.5,63.3),(25.3,65),(24,65.8),(22,65.5),(19.5,63.5),(17.5,62.3),(17.2,61),(18.8,60),
     (16.6,57),(14.3,55.5),(12.9,55.6),(11.8,58),(10.6,59.3),(8,58.1),(5.5,58.8),(5,61),
     (6.5,62.6),(10,64),(12.5,66),(15,68.5),(19,70),(25,71),(28.5,71),(31,70),(33,69.3),
     (40,67.5),(41,66.4),(44,68.5),(53,68.5),(58,69),(60,69.8),(68,68.5),(69,73),(73,72.5),
     (72,66.5),(80,72),(87,75),(100,77.5),(105,78),(113,74),(124,73.5),(130,71),(140,72.5),
     (150,71.5),(160,70),(170,69.8),(180,68.5),(180,65),(178,64.6),(176,62.5),(171,60),
     (165,60),(163.5,59.9),(162,57.8),(163,56),(160,53),(156.5,51),(156,57.5),(160,61),
     (156,61.5),(152,59),(145,59.4),(140,58),(137,54),(140.5,53),(141,48),(138,45),
     (135,43.3),(132,43),(129.5,41),(129.5,36),(126.5,34.5),(126.2,37.5),(124.6,39.6),
     (121.5,39),(121,40.9),(118,39),(117.6,38.5),(119,37),(122.5,37),(120.5,36),(119,35),
     (121,32),(122,30),(120,26),(116,22.8),(110.5,21.2),(108,21.5),(106.7,20),(105.8,18.5),
     (108.8,15.3),(109.2,11.5),(106.5,9.5),(105,8.6),(103,10.5),(100,13.5),(99.2,10.5),
     (100.5,7.5),(103.4,4),(104.3,1.3),(103.5,1.3),(100.3,3.5),(98.5,8),(98.2,12),
     (97.6,16.5),(94.3,16),(94.5,19.5),(92.3,21),(91,22.5),(88,21.7),(87,20.5),(84,18),
     (80.2,15.5),(80.2,13),(79.8,10.3),(77.5,8),(76.5,8.8),(74.5,14),(72.8,19),(72.6,21.4),
     (70,22.5),(68.5,23.5),(66.6,25.4),(61.6,25.2),(57.3,25.8),(56.4,27),(54.5,26.5),
     (51.6,27.8),(50,30),(48,30),(48.5,28.3),(50.2,26),(51.5,25),(51.6,24),(54.3,24.2),
     (56,26.2),(56.4,24.7),(59.8,22.5),(58.5,20.5),(55.5,17.9),(52.2,16),(48.7,14),
     (43.5,12.7),(42.7,15.7),(40.8,19.7),(38.7,22.5),(37,25.8),(35,28),(34.6,29.5),
     (34.2,31.2),(34.9,32.8),(35.9,35.3),(36.2,36.7),(32.5,36.1),(30.5,36.3),(28,36.7),
     (26.3,38.2),(26.5,40.2),(29,41.1),(31.2,41.2),(35,42),(38.3,40.9),(41.5,41.5),
     (39.5,44),(37.5,44.7),(38.3,46.2),(35,45.6),(33.5,44.5),(32.5,45.3),(33.5,46),
     (31.5,46.6),(30,45.8),(28.8,44.5),(27.7,42.6),(28,41.5),(26.2,40.8),(23.8,40.8),
     (22.6,40.3),(23.4,39.2),(22.6,38.3),(23.2,37.4),(22.8,36.5),(21.7,36.9),(21.1,38.3),
     (19.4,40.3),(19.5,41.8),(16.1,43.5),(13.7,45.1),(12.3,45.3),(12.5,44.3),(13.6,43.5),
     (15.9,41.6),(18.5,40.2),(17.2,39.4),(16.6,38.9),(15.7,38),(15.6,40.1),(12.3,41.7),
     (10.5,42.9),(8.9,44.4),(6.6,43.1),(4.6,43.4),(3.1,43),(3.2,41.9),(0.9,41),(-0.3,39.3),
     (0.2,38.7),(-0.7,37.6),(-2.1,36.7),(-4.4,36.7),(-5.4,35.9),(-6.5,36.9),(-7.5,37.1),
     (-9,37)],
    # Europe islands
    [(-5.7,50),(1.5,51.2),(1.7,52.7),(0,53.5),(-1.5,55),(-2,57.6),(-3.5,58.6),(-5,58.6),
     (-6.2,56.5),(-5,55),(-3,54.5),(-3.2,53.4),(-4.7,52.8),(-5.2,51.7),(-3,51.4)],
    [(-10,51.6),(-6,52.2),(-6,54),(-7.5,55.3),(-10,54.2)],
    [(-24,65.5),(-18,66.5),(-13.5,65.3),(-15,64.3),(-20,63.4),(-22.5,64)],
    [(11,78.5),(16,80),(27,80),(20,77.5),(15,77)],
    [(52,71.5),(56,73.5),(68,77),(60,76),(55,74.5)],
    [(8.5,41),(9.8,41),(9.6,39),(8.4,39)],                       # Sardinia
    [(12.4,38.1),(15.6,38.2),(15.1,36.7),(12.5,37.6)],           # Sicily
    # Asia islands
    [(130,31),(131.5,31.5),(132,33.8),(135,33.5),(137,34.6),(140,35),(141,38.5),(142,40),
     (141.3,41.4),(140,40.5),(139.8,38),(137,37),(135.5,35.5),(132.5,35.5),(130.8,34)],
    [(140,41.5),(143.5,42),(145.5,43.3),(142,45.4),(140,43.2)],
    [(142,46),(143.5,49),(143,54),(142,54)],
    [(120.2,22.5),(121.9,25),(121.5,25.3),(120.1,23.5)],          # Taiwan
    [(108.6,19.2),(111,19.8),(110.3,18.3)],                       # Hainan
    [(79.8,6),(81.8,7),(80.2,9.8)],
    [(95.3,5.6),(98,4),(104,-2),(106,-5.8),(102,-4)],
    [(105.2,-6.8),(114.5,-7.8),(114.5,-8.7),(106,-7.5)],
    [(109,1.5),(111,1.5),(113,3),(116,6.5),(119,5),(118,1),(116,-3.5),(110.5,-3),(109,-0.5)],
    [(119.5,-5.5),(120.5,0.5),(124.8,1.3),(121,0.5),(123.3,-1),(121.5,-1.8),(122.5,-4.5),
     (120.5,-2.5),(120.5,-5.5)],
    [(131,-1),(135,-3.2),(138,-1.5),(141,-2.6),(146,-5.5),(150.5,-10.5),(147,-10),
     (144,-7.7),(141,-9.2),(138,-8.3),(137.5,-5),(132,-4)],
    [(120,18.5),(122.3,18.5),(122,14),(124,12.5),(120.5,14.2),(120,16)],
    [(122,7),(126,7),(126.5,9.5),(125,9),(123.5,8)],
    # Oceania
    [(114,-22),(114,-26.5),(115,-34),(118,-35),(123.5,-34),(127,-32.3),(131,-31.5),
     (135,-34.5),(137.5,-33),(138,-35.5),(140,-38),(144,-38.3),(147,-38),(150,-37.5),
     (151.3,-33.8),(153.5,-28.5),(153,-25.2),(150.8,-22.5),(146.5,-19),(145.4,-15),
     (143.6,-14),(142.5,-10.7),(141.5,-13),(141.6,-17),(140,-17.7),(136,-15.5),(137,-12.3),
     (132.5,-11.4),(130,-13),(129.5,-15),(126.8,-13.8),(124,-16.3),(122.2,-18),(119,-20)],
    [(144.6,-40.7),(148.3,-40.9),(148,-43.2),(146,-43.5)],
    [(172.7,-34.5),(178.5,-37.7),(177,-39.5),(175,-41.5),(173.8,-39.2),(174.5,-36.5)],
    [(172.7,-40.5),(174.3,-41.8),(171,-44.5),(169,-46.6),(166.5,-46),(168,-44)],
]

LAT_TOP, LAT_BOT = 83.0, -56.0
LON_L, LON_R = -180.0, 180.0

# --------------------------------------------------------------------------
# Countries: code -> (name, lat, lon, target weight, source weight)
# --------------------------------------------------------------------------

COUNTRIES = {
    "US": ("United States", 39.0, -98.0, 25, 20),
    "CA": ("Canada", 45.5, -75.0, 3, 1.5),
    "MX": ("Mexico", 21.0, -101.0, 2, 1),
    "BR": ("Brazil", -14.0, -51.0, 4, 4),
    "AR": ("Argentina", -34.0, -64.0, 1, 0.5),
    "CO": ("Colombia", 4.6, -74.0, 1.2, 0.6),
    "CL": ("Chile", -33.4, -70.6, 1, 0.4),
    "PE": ("Peru", -12.0, -77.0, 0.8, 0.3),
    "GB": ("United Kingdom", 52.5, -1.5, 5, 3),
    "IE": ("Ireland", 53.3, -7.8, 1, 1),
    "FR": ("France", 46.6, 2.4, 3, 3),
    "DE": ("Germany", 51.0, 10.4, 5, 5),
    "NL": ("Netherlands", 52.2, 5.3, 2, 5),
    "ES": ("Spain", 40.2, -3.7, 2, 1),
    "IT": ("Italy", 42.8, 12.5, 2, 1),
    "PL": ("Poland", 52.0, 19.0, 1.5, 1),
    "SE": ("Sweden", 59.3, 18.0, 1, 0.8),
    "UA": ("Ukraine", 49.0, 31.5, 1.5, 2),
    "RU": ("Russia", 55.7, 37.6, 2, 10),
    "TR": ("Turkey", 39.0, 35.0, 2, 2),
    "IL": ("Israel", 31.5, 34.8, 2, 0.8),
    "IR": ("Iran", 32.4, 53.7, 1, 3),
    "SA": ("Saudi Arabia", 24.0, 45.0, 1.5, 0.5),
    "AE": ("United Arab Emirates", 24.4, 54.4, 1.5, 0.6),
    "EG": ("Egypt", 26.8, 30.8, 1, 0.6),
    "MA": ("Morocco", 31.8, -7.0, 0.8, 0.4),
    "NG": ("Nigeria", 9.0, 8.7, 1.5, 1.2),
    "KE": ("Kenya", -0.5, 37.9, 1, 0.4),
    "ZA": ("South Africa", -29.0, 25.0, 2, 0.8),
    "KZ": ("Kazakhstan", 48.0, 67.0, 0.6, 0.6),
    "IN": ("India", 21.0, 78.0, 9, 4),
    "PK": ("Pakistan", 30.0, 70.0, 1, 1),
    "BD": ("Bangladesh", 23.7, 90.4, 0.8, 0.6),
    "CN": ("China", 34.0, 108.0, 3, 12),
    "HK": ("Hong Kong", 22.3, 114.2, 1.5, 3),
    "TW": ("Taiwan", 23.7, 121.0, 3, 0.6),
    "KR": ("South Korea", 36.5, 127.8, 2, 1.5),
    "KP": ("North Korea", 40.0, 127.0, 0.1, 3),
    "JP": ("Japan", 36.2, 138.3, 4, 1),
    "VN": ("Vietnam", 16.0, 107.8, 1.2, 3),
    "TH": ("Thailand", 15.8, 101.0, 1.2, 0.8),
    "SG": ("Singapore", 1.35, 103.8, 2, 3),
    "MY": ("Malaysia", 4.2, 101.9, 1, 0.8),
    "ID": ("Indonesia", -2.5, 118.0, 2, 2),
    "PH": ("Philippines", 12.9, 121.8, 1.5, 0.6),
    "AU": ("Australia", -25.3, 133.8, 3, 1),
    "NZ": ("New Zealand", -41.0, 174.0, 0.8, 0.3),
}

ATTACK_TYPES = {
    "malware": {
        "label": "Malware", "weight": 52,
        "names": ["FakeUpdates", "Androxgh0st", "Remcos", "AgentTesla", "Formbook",
                  "Qbot", "Lumma Stealer", "AsyncRAT", "XMRig", "Ramnit", "Mirai",
                  "njRAT", "Phorpiex", "Snake Keylogger", "Vidar", "AZORult"],
    },
    "phishing": {
        "label": "Phishing", "weight": 17,
        "names": ["Credential Harvest", "Fake Invoice", "BEC Lure", "Spoofed Login",
                  "Delivery Notice", "Tax Refund Lure", "QR-code Phish", "MFA Fatigue",
                  "Fake Payroll Update", "Shared-Doc Lure"],
    },
    "exploit": {
        "label": "Exploit", "weight": 31,
        "names": ["Log4Shell RCE", "MOVEit SQLi", "Citrix Bleed", "ProxyShell",
                  "Apache Struts RCE", "PAN-OS Cmd Injection", "Ivanti VPN Bypass",
                  "PHP-CGI Arg Injection", "Dir Traversal", "HTTP Header RCE",
                  "Confluence OGNL", "SMB Remote Code Exec"],
    },
}
TYPE_ORDER = ["malware", "phishing", "exploit"]

INDUSTRIES = [("Education", 24), ("Government", 14), ("Healthcare", 11),
              ("Communications", 9), ("ISP/MSP", 9), ("Manufacturing", 8),
              ("Finance", 8), ("Consumer Goods", 6), ("Retail", 6),
              ("Utilities", 5)]

# Extra country centroids so real data (Radar, logs) can place any country.
EXTRA_COORDS = {
    'AF': ('Afghanistan', 33.9, 67.7),
    'AL': ('Albania', 41.2, 20.2),
    'DZ': ('Algeria', 28.0, 1.7),
    'AO': ('Angola', -11.2, 17.9),
    'AM': ('Armenia', 40.1, 45.0),
    'AT': ('Austria', 47.5, 14.6),
    'AZ': ('Azerbaijan', 40.1, 47.6),
    'BH': ('Bahrain', 26.0, 50.6),
    'BY': ('Belarus', 53.7, 28.0),
    'BE': ('Belgium', 50.5, 4.5),
    'BJ': ('Benin', 9.3, 2.3),
    'BO': ('Bolivia', -16.3, -63.6),
    'BA': ('Bosnia & Herz.', 43.9, 17.7),
    'BW': ('Botswana', -22.3, 24.7),
    'BG': ('Bulgaria', 42.7, 25.5),
    'BF': ('Burkina Faso', 12.2, -1.6),
    'KH': ('Cambodia', 12.6, 104.9),
    'CM': ('Cameroon', 7.4, 12.4),
    'CR': ('Costa Rica', 9.7, -83.8),
    'HR': ('Croatia', 45.1, 15.2),
    'CU': ('Cuba', 21.5, -77.8),
    'CY': ('Cyprus', 35.1, 33.4),
    'CZ': ('Czechia', 49.8, 15.5),
    'CD': ('DR Congo', -4.0, 21.8),
    'DK': ('Denmark', 56.3, 9.5),
    'DO': ('Dominican Rep.', 18.7, -70.2),
    'EC': ('Ecuador', -1.8, -78.2),
    'SV': ('El Salvador', 13.8, -88.9),
    'EE': ('Estonia', 58.6, 25.0),
    'ET': ('Ethiopia', 9.1, 40.5),
    'FI': ('Finland', 61.9, 25.7),
    'GE': ('Georgia', 42.3, 43.4),
    'GH': ('Ghana', 7.9, -1.0),
    'GR': ('Greece', 39.1, 21.8),
    'GT': ('Guatemala', 15.8, -90.2),
    'HN': ('Honduras', 15.2, -86.2),
    'HU': ('Hungary', 47.2, 19.5),
    'IS': ('Iceland', 64.9, -19.0),
    'IQ': ('Iraq', 33.2, 43.7),
    'JM': ('Jamaica', 18.1, -77.3),
    'JO': ('Jordan', 30.6, 36.2),
    'KW': ('Kuwait', 29.3, 47.5),
    'KG': ('Kyrgyzstan', 41.2, 74.8),
    'LA': ('Laos', 19.9, 102.5),
    'LV': ('Latvia', 56.9, 24.6),
    'LB': ('Lebanon', 33.9, 35.9),
    'LY': ('Libya', 26.3, 17.2),
    'LT': ('Lithuania', 55.2, 23.9),
    'LU': ('Luxembourg', 49.8, 6.1),
    'MG': ('Madagascar', -18.8, 46.9),
    'MW': ('Malawi', -13.3, 34.3),
    'ML': ('Mali', 17.6, -4.0),
    'MT': ('Malta', 35.9, 14.4),
    'MU': ('Mauritius', -20.3, 57.6),
    'MD': ('Moldova', 47.4, 28.4),
    'MN': ('Mongolia', 46.9, 103.8),
    'ME': ('Montenegro', 42.7, 19.4),
    'MZ': ('Mozambique', -18.7, 35.5),
    'MM': ('Myanmar', 21.9, 95.9),
    'NA': ('Namibia', -22.9, 18.5),
    'NP': ('Nepal', 28.4, 84.1),
    'NI': ('Nicaragua', 12.9, -85.2),
    'NE': ('Niger', 17.6, 8.1),
    'MK': ('North Macedonia', 41.6, 21.7),
    'NO': ('Norway', 60.5, 8.5),
    'OM': ('Oman', 21.5, 55.9),
    'PA': ('Panama', 8.5, -80.8),
    'PY': ('Paraguay', -23.4, -58.4),
    'PT': ('Portugal', 39.4, -8.2),
    'PR': ('Puerto Rico', 18.2, -66.6),
    'QA': ('Qatar', 25.4, 51.2),
    'RO': ('Romania', 45.9, 25.0),
    'RW': ('Rwanda', -1.9, 29.9),
    'RS': ('Serbia', 44.0, 21.0),
    'SN': ('Senegal', 14.5, -14.5),
    'SK': ('Slovakia', 48.7, 19.7),
    'SI': ('Slovenia', 46.2, 15.0),
    'LK': ('Sri Lanka', 7.9, 80.8),
    'SD': ('Sudan', 12.9, 30.2),
    'CH': ('Switzerland', 46.8, 8.2),
    'SY': ('Syria', 34.8, 39.0),
    'TJ': ('Tajikistan', 38.9, 71.3),
    'TZ': ('Tanzania', -6.4, 34.9),
    'TN': ('Tunisia', 34.0, 9.5),
    'TM': ('Turkmenistan', 39.0, 59.6),
    'UG': ('Uganda', 1.4, 32.3),
    'UY': ('Uruguay', -32.5, -55.8),
    'UZ': ('Uzbekistan', 41.4, 64.6),
    'VE': ('Venezuela', 6.4, -66.6),
    'YE': ('Yemen', 15.6, 48.5),
    'ZM': ('Zambia', -13.1, 27.8),
    'ZW': ('Zimbabwe', -19.0, 29.2),
    'CI': ("Cote d'Ivoire", 7.5, -5.5),
    'SC': ('Seychelles', -4.7, 55.5),
    'MO': ('Macao', 22.2, 113.5),
    'BN': ('Brunei', 4.5, 114.7),
    'BT': ('Bhutan', 27.5, 90.4),
    'PS': ('Palestine', 31.9, 35.2),
    'GL': ('Greenland', 72.0, -40.0),
    'BZ': ('Belize', 17.2, -88.5),
    'TT': ('Trinidad & Tobago', 10.7, -61.2),
    'BS': ('Bahamas', 25.0, -77.4),
    'HT': ('Haiti', 19.0, -72.3),
    'GN': ('Guinea', 9.9, -9.7),
    'SL': ('Sierra Leone', 8.5, -11.8),
    'LR': ('Liberia', 6.4, -9.4),
    'TG': ('Togo', 8.6, 0.8),
    'GA': ('Gabon', -0.8, 11.6),
    'CG': ('Congo', -0.2, 15.8),
    'SO': ('Somalia', 5.2, 46.2),
    'ER': ('Eritrea', 15.2, 39.8),
    'DJ': ('Djibouti', 11.8, 42.6),
    'LS': ('Lesotho', -29.6, 28.2),
    'SZ': ('Eswatini', -26.5, 31.5),
    'FJ': ('Fiji', -17.7, 178.1),
    'PG': ('Papua New Guinea', -6.3, 143.9),
    'GU': ('Guam', 13.4, 144.8),
    'RE': ('Reunion', -21.1, 55.5),
    'AD': ('Andorra', 42.5, 1.5),
    'MC': ('Monaco', 43.7, 7.4),
    'LI': ('Liechtenstein', 47.2, 9.6),
    'SM': ('San Marino', 43.9, 12.5),
    'GI': ('Gibraltar', 36.1, -5.4),
    'IM': ('Isle of Man', 54.2, -4.5),
    'JE': ('Jersey', 49.2, -2.1),
    'GG': ('Guernsey', 49.5, -2.6),
    'FO': ('Faroe Islands', 62.0, -6.8),
    'AW': ('Aruba', 12.5, -70.0),
    'CW': ('Curacao', 12.2, -69.0),
    'KY': ('Cayman Islands', 19.3, -81.3),
    'BM': ('Bermuda', 32.3, -64.8),
    'VG': ('British Virgin Is.', 18.4, -64.6),
    'XK': ('Kosovo', 42.6, 20.9),
    'SS': ('South Sudan', 6.9, 31.3),
    'TD': ('Chad', 15.4, 18.7),
    'CF': ('Central African Rep.', 6.6, 20.9),
    'MR': ('Mauritania', 21.0, -10.9),
    'GM': ('Gambia', 13.4, -15.3),
    'GW': ('Guinea-Bissau', 11.8, -15.2),
    'CV': ('Cape Verde', 16.0, -24.0),
    'BI': ('Burundi', -3.4, 29.9),
    'MV': ('Maldives', 3.2, 73.2),
    'TL': ('Timor-Leste', -8.9, 125.7),
    'NC': ('New Caledonia', -21.3, 165.6),
    'PF': ('French Polynesia', -17.7, -149.4),
    'WS': ('Samoa', -13.8, -172.1),
    'GY': ('Guyana', 4.9, -58.9),
    'SR': ('Suriname', 3.9, -56.0),
    'GF': ('French Guiana', 4.0, -53.0),
}

# --------------------------------------------------------------------------
# Palette.  key -> (256-colour fg, 8-colour fg, bold)
# --------------------------------------------------------------------------

BG256 = 233
PALETTE = {
    "base":         (250, 7,   False),
    "land":         (240, 4,    False),
    "land_solid":   (238, 4,    False),
    "text":         (252, 7,   False),
    "bright":       (255, 7,   True),
    "dim":          (244, 7,   False),
    "faint":        (238, 0,   True),
    "accent":       (197, 5, True),
    "malware":      (198, 5, True),
    "malware_dim":  (125, 5, False),
    "phishing":     (214, 3,  True),
    "phishing_dim": (130, 3,  False),
    "exploit":      (45,  6,    True),
    "exploit_dim":  (31,  6,    False),
    "off":          (239, 0,   True),
}

BRAILLE_BITS = {(0, 0): 0x01, (0, 1): 0x02, (0, 2): 0x04, (1, 0): 0x08,
                (1, 1): 0x10, (1, 2): 0x20, (0, 3): 0x40, (1, 3): 0x80}
BAR_PARTIALS = " ▏▎▍▌▋▊▉█"


def fmt_int(n):
    return f"{int(n):,}"


def weighted_choice(rng, items):
    """items: list of (value, weight)"""
    total = sum(w for _, w in items)
    r = rng.random() * total
    for v, w in items:
        r -= w
        if r <= 0:
            return v
    return items[-1][0]


# --------------------------------------------------------------------------
# Off-screen cell grid.  Rendering composes into this; curses and the ANSI
# snapshot both blit from it.
# --------------------------------------------------------------------------

class Grid:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.ch = [[" "] * w for _ in range(h)]
        self.at = [["base"] * w for _ in range(h)]

    def put(self, x, y, c, a):
        if 0 <= x < self.w and 0 <= y < self.h:
            self.ch[y][x] = c
            self.at[y][x] = a

    def text(self, x, y, s, a, maxw=None):
        if maxw is not None:
            s = s[:max(0, maxw)]
        for i, c in enumerate(s):
            self.put(x + i, y, c, a)

    def runs(self, y):
        row_c, row_a = self.ch[y], self.at[y]
        start, cur = 0, row_a[0]
        for x in range(1, self.w + 1):
            if x == self.w or row_a[x] != cur:
                yield start, "".join(row_c[start:x]), cur
                if x < self.w:
                    start, cur = x, row_a[x]


# --------------------------------------------------------------------------
# Map raster
# --------------------------------------------------------------------------

class WorldMap:
    def __init__(self, cols, rows, style="dots"):
        self.cols, self.rows, self.style = cols, rows, style
        self.pw, self.ph = cols * 2, rows * 4
        span_lon, span_lat = LON_R - LON_L, LAT_TOP - LAT_BOT
        # Fill the available area; allow a little non-uniform stretch so the
        # map doesn't float in empty space, but cap distortion.
        self.sx = self.pw / span_lon
        self.sy = max(self.sx * 0.8, min(self.ph / span_lat, self.sx * 1.3))
        if span_lat * self.sy > self.ph:
            self.sy = self.ph / span_lat
            self.sx = min(self.sx, self.sy / 0.8)
        self.ox = (self.pw - span_lon * self.sx) / 2
        self.oy = (self.ph - span_lat * self.sy) / 2
        self.cells = self._rasterize()

    def project(self, lat, lon):
        return (self.ox + (lon - LON_L) * self.sx,
                self.oy + (LAT_TOP - lat) * self.sy)

    def _rasterize(self):
        cells = [[0] * self.cols for _ in range(self.rows)]
        polys = [[self.project(lat, lon) for lon, lat in poly] for poly in LAND]
        for py in range(self.ph):
            yc = py + 0.5
            if self.style == "dots" and py % 2:
                continue
            for poly in polys:
                xs = []
                n = len(poly)
                for i in range(n):
                    x1, y1 = poly[i]
                    x2, y2 = poly[(i + 1) % n]
                    if (y1 <= yc < y2) or (y2 <= yc < y1):
                        xs.append(x1 + (yc - y1) * (x2 - x1) / (y2 - y1))
                xs.sort()
                for a, b in zip(xs[0::2], xs[1::2]):
                    for px in range(max(0, int(math.ceil(a - 0.5))),
                                    min(self.pw, int(math.floor(b - 0.5)) + 1)):
                        if self.style == "dots" and px % 2:
                            continue
                        cells[py // 4][px // 2] |= BRAILLE_BITS[(px % 2, py % 4)]
        return cells


# --------------------------------------------------------------------------
# Attacks & statistics
# --------------------------------------------------------------------------

TYPE_LABELS = {
    "demo":  {"malware": "Malware", "phishing": "Phishing", "exploit": "Exploit"},
    "feed":  {"malware": "Malware", "phishing": "Phishing", "exploit": "Exploit"},
    "radar": {"malware": "DDoS", "phishing": "Bots/bad IP", "exploit": "WAF/exploit"},
    "log":   {"malware": "Brute force", "phishing": "Scan/probe", "exploit": "Exploit"},
}
RADAR_NAMES = {"malware": ["HTTP flood", "L7 DDoS"], "phishing": ["Bad-reputation IP", "Bot traffic", "Access rule block"],
               "exploit": ["WAF rule match", "Exploit attempt", "API abuse"]}


def coords_for(code):
    code = (code or "").upper()
    if code in COUNTRIES:
        c = COUNTRIES[code]
        return c[0], c[1], c[2]
    return EXTRA_COORDS.get(code)


class Attack:
    __slots__ = ("src", "dst", "kind", "name", "detail", "born", "dur",
                 "src_name", "dst_name", "src_code", "dst_code")

    TAIL = 0.42      # trail length as a fraction of flight
    RIPPLE = 1.1     # seconds

    def __init__(self, src, dst, kind, name, detail, born):
        # src / dst: (code, name, lat, lon)
        self.src_code, self.src_name, *self.src = src
        self.dst_code, self.dst_name, *self.dst = dst
        self.kind, self.name, self.detail, self.born = kind, name, detail, born
        dlat, dlon = self.src[0] - self.dst[0], self.src[1] - self.dst[1]
        self.dur = 1.3 + min(1.0, math.hypot(dlat, dlon) / 200.0) * 1.7

    def done(self, now):
        return now - self.born > self.dur * (1 + self.TAIL) + self.RIPPLE


class Sim:
    """Holds the attacks on screen plus the statistics shown in the panels.

    mode:
      demo  – generated attacks (nothing real)
      feed  – events from a JSON-lines file
      log   – live attacks parsed from a firewall / web / SSH log
      radar – Cloudflare Radar layer-7 attack statistics (real, aggregated)
    """

    MAX_ARCS = 160

    def __init__(self, mode="demo", rate=3.5, seed=None):
        self.mode = mode
        self.rng = random.Random(seed)
        self.rate = rate
        self.enabled = set(TYPE_ORDER)
        self.attacks = []
        self.feed = collections.deque(maxlen=60)
        self.recent = collections.deque()        # wall timestamps, last 60s
        self.total = 0
        self.by_country = collections.Counter()  # display name -> count
        self.by_type = collections.Counter()
        self.by_extra = collections.Counter()    # industries / services
        self.radar = None                         # latest Radar snapshot
        self.status = ""                          # reader status line
        self._last_arc = {}
        self.today = 0
        self.per_arc = 1.0
        if mode == "demo":
            self._init_demo()

    def label(self, kind):
        return TYPE_LABELS[self.mode].get(kind, kind)

    # ----- demo -----
    def _init_demo(self):
        rng = self.rng
        sod = time.time() - datetime.now().replace(hour=0, minute=0, second=0,
                                                   microsecond=0).timestamp()
        # Each drawn arc stands for a batch of events so the day counter grows
        # at a believable global rate (~20M/day).
        self.per_arc = 240.0 / max(self.rate, 0.1)
        self.today = int(sod * 240 * rng.uniform(0.95, 1.05))
        self.by_country = collections.Counter(
            {v[0]: int(v[3] * rng.uniform(30, 60)) for v in COUNTRIES.values()})
        self.by_type = collections.Counter(
            {k: int(v["weight"] * rng.uniform(40, 55)) for k, v in ATTACK_TYPES.items()})
        self.by_extra = collections.Counter(
            {k: int(w * rng.uniform(40, 55)) for k, w in INDUSTRIES})
        self._tgt = [(c, v[3]) for c, v in COUNTRIES.items()]
        self._src = [(c, v[4]) for c, v in COUNTRIES.items()]
        self._types = [(k, v["weight"]) for k, v in ATTACK_TYPES.items()]

    def clear_stats(self):
        self.by_country.clear(); self.by_type.clear(); self.by_extra.clear()
        self.total = 0
        self.recent.clear()

    @staticmethod
    def resolve(loc):
        if isinstance(loc, str):
            c = coords_for(loc)
            return (loc.upper(), c[0], c[1], c[2]) if c else None
        if isinstance(loc, dict) and "lat" in loc and "lon" in loc:
            name = str(loc.get("name", "Unknown"))
            code = str(loc.get("code") or name[:2]).upper()
            return (code, name, float(loc["lat"]), float(loc["lon"]))
        return None

    def add(self, src, dst, kind, name, extra, detail, now, wall, count=True):
        kind = kind if kind in ATTACK_TYPES else "malware"
        if count:
            # In log mode every target is you, so rank attackers instead.
            self.by_country[src[1] if self.mode == "log" else dst[1]] += 1
            self.by_type[kind] += 1
            if extra:
                self.by_extra[extra] += 1
            self.total += 1
            self.today += self.per_arc * (self.rng.uniform(0.6, 1.4) if self.mode == "demo" else 1)
            self.recent.append(wall)
        if kind not in self.enabled or len(self.attacks) >= self.MAX_ARCS:
            return
        # Don't redraw the same source hammering the same thing every frame.
        key = (src[2], src[3], name)
        if self.mode == "log" and now - self._last_arc.get(key, -9) < 1.5:
            return
        self._last_arc[key] = now
        a = Attack(src, dst, kind, name, detail, now)
        self.attacks.append(a)
        self.feed.appendleft((datetime.fromtimestamp(wall).strftime("%H:%M:%S"), a))

    def _spawn_demo(self, now, wall):
        rng = self.rng
        dst_c = weighted_choice(rng, self._tgt)
        src_c = dst_c
        while src_c == dst_c:
            src_c = weighted_choice(rng, self._src)
        kind = weighted_choice(rng, self._types)
        name = rng.choice(ATTACK_TYPES[kind]["names"])
        industry = weighted_choice(rng, INDUSTRIES)
        self.add(self.resolve(src_c), self.resolve(dst_c), kind, name, industry, industry,
                 now, wall)

    def _spawn_radar(self, now, wall):
        snap = self.radar
        if not snap or not snap["pairs"]:
            return
        src, dst, share = weighted_choice(self.rng, [(p, p[2]) for p in snap["pairs"]])
        mix = snap.get("mix") or {"malware": 50, "phishing": 20, "exploit": 30}
        kind = weighted_choice(self.rng, [(k, v) for k, v in mix.items() if v > 0] or [("malware", 1)])
        name = self.rng.choice(RADAR_NAMES[kind])
        self.add(src, dst, kind, name, None, f"{share:.2f}% of 24h", now, wall, count=False)

    def step(self, now, dt, wall):
        if self.mode in ("demo", "radar"):
            lam = self.rate * dt
            L, p, k = math.exp(-lam), 1.0, 0     # Poisson draw for this frame
            while True:
                p *= self.rng.random()
                if p <= L:
                    break
                k += 1
            for _ in range(k):
                (self._spawn_demo if self.mode == "demo" else self._spawn_radar)(now, wall)
        self.attacks = [a for a in self.attacks if not a.done(now)]
        while self.recent and wall - self.recent[0] > 60:
            self.recent.popleft()
        if len(self._last_arc) > 5000:
            self._last_arc.clear()

    def per_minute(self):
        return len(self.recent) * (self.per_arc if self.mode == "demo" else 1)

    # ----- panel content -----
    @staticmethod
    def _rows(counter, n):
        total = sum(counter.values())
        return [(k, v / total if total else 0) for k, v in counter.most_common(n)]

    def panel(self, n_countries):
        """Returns (headline, sections, type_shares)."""
        if self.mode == "radar":
            snap = self.radar or {}
            upd = snap.get("updated")
            head = ("CLOUDFLARE RADAR · LAYER 7", "Last 24 hours",
                    "updated " + datetime.fromtimestamp(upd).strftime("%H:%M") if upd else "connecting…")
            secs = [("MOST ATTACKED COUNTRIES", [(n, v / 100) for n, v in snap.get("targets", [])][:n_countries]),
                    ("TOP ATTACK ORIGINS", [(n, v / 100) for n, v in snap.get("origins", [])])]
            mix = snap.get("mix") or {}
            tot = sum(mix.values())
            types = {k: (mix.get(k, 0) / tot if tot else 0) for k in TYPE_ORDER}
            return head, secs, types
        rate = f"{fmt_int(self.per_minute())}/min"
        if self.mode == "demo":
            head = ("ATTACKS TODAY", fmt_int(self.today), rate)
            secs = [("MOST ATTACKED COUNTRIES", self._rows(self.by_country, n_countries)),
                    ("TOP TARGETED INDUSTRIES", self._rows(self.by_extra, 10))]
        elif self.mode == "log":
            head = ("ATTACKS SEEN (THIS SESSION)", fmt_int(self.total), rate)
            secs = [("TOP ATTACKING COUNTRIES", self._rows(self.by_country, n_countries)),
                    ("MOST TARGETED SERVICES", self._rows(self.by_extra, 10))]
        else:
            head = ("EVENTS RECEIVED", fmt_int(self.total), rate)
            secs = [("MOST ATTACKED COUNTRIES", self._rows(self.by_country, n_countries)),
                    ("TOP TARGETED INDUSTRIES", self._rows(self.by_extra, 10))]
        tot = sum(self.by_type.values())
        types = {k: (self.by_type[k] / tot if tot else 0) for k in TYPE_ORDER}
        return head, secs, types

    def detail_title(self):
        return {"demo": "INDUSTRY", "feed": "INDUSTRY", "log": "ATTACKER IP",
                "radar": "SHARE"}[self.mode]

    def source_note(self):
        return {"demo": "simulated data · --radar or --log for real data",
                "feed": "live: JSON feed",
                "log": "live: your log · geolocation ip-api.com",
                "radar": "real data: Cloudflare Radar · 24h aggregate, arcs sampled from it"}[self.mode]


# --------------------------------------------------------------------------
# Data sources (background threads)
# --------------------------------------------------------------------------

def http_json(url, headers=None, data=None, timeout=15):
    h = {"User-Agent": "threatscope/1.1", "Accept": "application/json"}
    h.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class FeedReader(threading.Thread):
    """Tails a JSON-lines file and queues events."""

    def __init__(self, path, q):
        super().__init__(daemon=True)
        self.path, self.q = path, q
        self.error = None
        self.snapshot = None

    def run(self):
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.q.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except OSError as e:
            self.error = str(e)


class RadarReader(threading.Thread):
    """Polls Cloudflare Radar for layer-7 (HTTP) attack statistics.

    Radar publishes aggregates — shares of all attack traffic Cloudflare
    mitigated — not individual attack events. The map samples arcs from
    those real origin→target shares.
    """

    API = "https://api.cloudflare.com/client/v4"

    def __init__(self, token, interval=300, limit=20):
        super().__init__(daemon=True)
        self.token = token
        self.interval = max(60.0, float(interval))
        self.limit = max(1, min(25, int(limit)))
        self.snapshot = None     # set when a new poll lands; Engine picks it up
        self.error = None
        self.q = None

    def _get(self, path, **params):
        params.setdefault("dateRange", "1d")
        params.setdefault("format", "json")
        url = f"{self.API}{path}?{urllib.parse.urlencode(params)}"
        d = http_json(url, {"Authorization": f"Bearer {self.token}"})
        if not d.get("success", True):
            errs = d.get("errors") or [{}]
            raise RuntimeError(errs[0].get("message", "Radar request failed"))
        return d.get("result", {})

    @staticmethod
    def _pick(result, name):
        if name in result:
            return result[name]
        for k, v in result.items():
            if k != "meta" and isinstance(v, (list, dict)):
                return v
        return None

    def poll(self):
        res = self._get("/radar/attacks/layer7/top/attacks", limit=self.limit, name="pairs")
        pairs = []
        for row in self._pick(res, "pairs") or []:
            o, t = row.get("originCountryAlpha2"), row.get("targetCountryAlpha2")
            oc, tc = coords_for(o), coords_for(t)
            if not oc or not tc:
                continue
            on = row.get("originCountryName") or oc[0]
            tn = row.get("targetCountryName") or tc[0]
            pairs.append(((o, on, oc[1], oc[2]), (t, tn, tc[1], tc[2]), float(row.get("value", 0))))
        if not pairs:
            raise RuntimeError("Radar returned no attack pairs")

        def top(side):
            try:
                r = self._get(f"/radar/attacks/layer7/top/locations/{side}", limit=10, name="loc")
                key = f"{side}CountryName"
                return [(row.get(key, "?"), float(row.get("value", 0))) for row in self._pick(r, "loc") or []]
            except Exception:
                return []

        mix = None
        for path in ("/radar/attacks/layer7/summary/mitigation_product", "/radar/attacks/layer7/summary"):
            try:
                raw = self._pick(self._get(path, name="mix"), "mix") or {}
                if isinstance(raw, dict) and raw:
                    mix = {"malware": 0.0, "phishing": 0.0, "exploit": 0.0}
                    for k, v in raw.items():
                        k, v = k.lower(), float(v)
                        if k == "ddos":
                            mix["malware"] += v
                        elif k in ("ip_reputation", "access_rules", "bot_management"):
                            mix["phishing"] += v
                        else:
                            mix["exploit"] += v
                    break
            except Exception:
                continue

        self.snapshot = {"pairs": pairs, "targets": top("target"), "origins": top("origin"),
                         "mix": mix, "updated": time.time()}

    def run(self):
        while True:
            try:
                self.poll()
                wait = self.interval
            except urllib.error.HTTPError as e:
                self.error = ("Radar token rejected — it needs the Radar: Read permission"
                              if e.code in (401, 403) else f"Radar HTTP {e.code}")
                wait = 60
            except Exception as e:
                self.error = f"Radar: {e}"
                wait = 60
            time.sleep(wait)


# ----- log parsing -----

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 1433: "MS-SQL", 1723: "PPTP VPN", 1900: "UPnP",
    2323: "Telnet", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 7547: "TR-069", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
BRUTE_PORTS = {21, 22, 23, 25, 110, 143, 1433, 2323, 3306, 3389, 5432, 5900}

WEB_EXPLOITS = [
    ("jndi:", "Log4Shell"), ("/.env", ".env file grab"), ("/.git", "Git repo grab"),
    ("wp-login", "WordPress login"), ("xmlrpc.php", "WordPress XML-RPC"),
    ("phpmyadmin", "phpMyAdmin probe"), ("/vendor/phpunit", "PHPUnit RCE"),
    ("/cgi-bin/", "CGI exploit"), ("../", "Path traversal"), ("%2e%2e", "Path traversal"),
    ("/boaform", "Router exploit"), ("/hnap1", "Router exploit"), ("/actuator", "Spring actuator"),
    ("union%20select", "SQL injection"), ("union+select", "SQL injection"),
    ("select%20", "SQL injection"), ("<script", "XSS attempt"), ("%3cscript", "XSS attempt"),
    ("/owa/", "Exchange OWA probe"), ("/autodiscover", "Exchange probe"),
    ("shell", "Web shell probe"), ("eval(", "Code injection"), ("/wp-admin", "WordPress admin"),
    ("/admin", "Admin panel probe"), ("/config", "Config file grab"),
]
ACCESS_RE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3})')
SSH_RE = re.compile(r"(Failed password|Invalid user|authentication failure|Connection closed by authenticating"
                    r"|maximum authentication attempts).*?(?:from|rhost=)\s*([0-9A-Fa-f:.]+)")
BAN_RE = re.compile(r"fail2ban.*\bBan ([0-9A-Fa-f:.]+)")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def public_ip(s):
    try:
        ip = ipaddress.ip_address(s.strip("[]"))
        return str(ip) if ip.is_global else None
    except ValueError:
        return None


class LogParser:
    """Turns log lines into (ip, kind, name, service). Handles the Windows
    Firewall log (pfirewall.log), nginx/Apache access logs, SSH auth logs and
    fail2ban; anything else with a public IP counts only with --log-all."""

    FW_DEFAULT = ["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port",
                  "dst-port", "size", "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype",
                  "icmpcode", "info", "path", "pid"]

    def __init__(self, include_all=False):
        self.include_all = include_all
        self.fw_fields = None

    def parse(self, line):
        line = line.strip()
        if not line:
            return None
        if line.startswith("#Fields:"):
            self.fw_fields = line.split()[1:]
            return None
        if line.startswith("#"):
            return None

        parts = line.split()
        if len(parts) >= 8 and re.match(r"\d{4}-\d{2}-\d{2}$", parts[0]) and parts[2] in ("DROP", "ALLOW", "INFO-EVENTS-LOST"):
            f = dict(zip(self.fw_fields or self.FW_DEFAULT, parts))
            if f.get("action") != "DROP" or f.get("path", "RECEIVE") not in ("RECEIVE", "-"):
                return None
            ip = public_ip(f.get("src-ip", ""))
            if not ip:
                return None
            try:
                port = int(f.get("dst-port", "-"))
            except ValueError:
                port = None
            proto = f.get("protocol", "")
            svc = SERVICE_PORTS.get(port, f"{proto} {port}" if port else proto or "ICMP")
            if port in BRUTE_PORTS:
                return ip, "malware", f"{svc} access attempt", svc
            return ip, "phishing", f"Blocked {svc} probe", svc

        m = ACCESS_RE.match(line)
        if m:
            ip = public_ip(m.group(1))
            if not ip:
                return None
            method, path, status = m.group(2), m.group(3), int(m.group(4))
            low = path.lower()
            for pat, name in WEB_EXPLOITS:
                if pat in low:
                    return ip, "exploit", name, "HTTP"
            if status == 401 or (method == "POST" and "login" in low and status in (200, 302, 403)):
                return ip, "malware", "Web login attempt", "HTTP"
            if status in (400, 404, 405, 444):
                return ip, "phishing", f"{status} probe {path[:24]}", "HTTP"
            if self.include_all:
                return ip, "phishing", f"{method} {path[:24]}", "HTTP"
            return None

        m = SSH_RE.search(line)
        if m:
            ip = public_ip(m.group(2))
            return (ip, "malware", "SSH login attempt", "SSH") if ip else None
        m = BAN_RE.search(line)
        if m:
            ip = public_ip(m.group(1))
            return (ip, "malware", "Banned by fail2ban", "fail2ban") if ip else None

        if self.include_all:
            for cand in IPV4_RE.findall(line):
                ip = public_ip(cand)
                if ip:
                    return ip, "phishing", "Logged connection", "Other"
        return None


class LogReader(threading.Thread):
    """Tails a log file, geolocates attacker IPs (ip-api.com, free, no key) and
    queues one event per attack with your own location as the target."""

    GEO_BATCH = "http://ip-api.com/batch?fields=status,country,countryCode,lat,lon,query"
    GEO_SELF = "http://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon"

    def __init__(self, path, q, here=None, replay=False, include_all=False):
        super().__init__(daemon=True)
        self.path, self.q, self.replay = path, q, replay
        self.parser = LogParser(include_all)
        self.here = here
        self.cache = {}
        self.pending = []
        self.last_batch = 0.0
        self.last_here_try = 0.0
        self.error = None
        self.snapshot = None

    def _locate_self(self):
        if self.here is not None or time.time() - self.last_here_try < 30:
            return
        self.last_here_try = time.time()
        try:
            d = http_json(self.GEO_SELF)
            if d.get("status") == "success":
                name = f"You ({d.get('city') or d.get('country')})"
                self.here = {"lat": d["lat"], "lon": d["lon"], "name": name, "code": "YOU"}
        except Exception as e:
            self.error = f"Couldn't find your location ({e}); pass --here LAT,LON"

    def _geolocate(self):
        todo = [ip for ip in dict.fromkeys(p[0] for p in self.pending) if ip not in self.cache][:100]
        if not todo or time.time() - self.last_batch < 4.5:     # free tier: 15 batches/min
            return
        self.last_batch = time.time()
        try:
            for r in http_json(self.GEO_BATCH, data=todo):
                ip = r.get("query")
                if r.get("status") == "success":
                    self.cache[ip] = {"lat": r["lat"], "lon": r["lon"],
                                      "name": r.get("country") or "Unknown",
                                      "code": r.get("countryCode") or "??"}
                else:
                    self.cache[ip] = None
        except Exception as e:
            self.error = f"Geolocation failed ({e}); retrying"

    def _flush(self):
        if self.here is None:
            return
        keep, now = [], time.time()
        for ip, kind, name, svc, seen in self.pending:
            if ip in self.cache:
                loc = self.cache[ip]
                if loc:
                    self.q.append({"src": loc, "dst": self.here, "type": kind, "name": name,
                                   "industry": svc, "detail": ip})
            elif now - seen < 120:
                keep.append((ip, kind, name, svc, seen))
        self.pending = keep[-2000:]

    def run(self):
        f, pos = None, 0
        while True:
            try:
                if f is None:
                    f = open(self.path, "r", encoding="utf-8", errors="replace")
                    if not self.replay:
                        f.seek(0, os.SEEK_END)
                    self.replay = True          # after a rotation, read the new file from the start
                    pos = f.tell()
                if os.path.getsize(self.path) < pos:  # log rotated / truncated
                    f.close(); f = None
                    continue
                for _ in range(2000):
                    line = f.readline()
                    if not line:
                        break
                    ev = self.parser.parse(line)
                    if ev:
                        self.pending.append((*ev, time.time()))
                pos = f.tell()
            except PermissionError:
                self.error = "Permission denied reading the log — run the terminal as Administrator"
                f = None
                time.sleep(5)
                continue
            except OSError as e:
                self.error = f"Can't read log: {e}"
                f = None
                time.sleep(5)
                continue
            self._locate_self()
            self._geolocate()
            self._flush()
            time.sleep(0.25)


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------

class App:
    PANEL_W = 36
    FEED_H = 9

    def __init__(self, sim, map_style="dots"):
        self.sim = sim
        self.map_style = map_style
        self.paused = False
        self.world = None
        self.layout_for = None
        self.status = ""
        self.status_until = 0

    # ----- layout -----
    def layout(self, W, H):
        if self.layout_for == (W, H, self.map_style):
            return
        self.layout_for = (W, H, self.map_style)
        self.show_panel = W >= 96
        self.feed_h = self.FEED_H if H >= 30 else (6 if H >= 22 else 0)
        self.map_x, self.map_y = 1, 2
        self.map_w = W - 2 - (self.PANEL_W + 1 if self.show_panel else 0)
        self.map_h = H - 2 - 1 - (self.feed_h + 1 if self.feed_h else 0)
        self.world = WorldMap(max(10, self.map_w), max(5, self.map_h), self.map_style)

    def flash(self, msg, now, secs=2.5):
        self.status, self.status_until = msg, now + secs

    # ----- frame -----
    def render(self, W, H, now, wall):
        g = Grid(W, H)
        if W < 60 or H < 18:
            msg = "Make the terminal at least 60×18"
            g.text(max(0, (W - len(msg)) // 2), H // 2, msg, "accent")
            return g
        self.layout(W, H)
        self.draw_header(g, W, wall)
        self.draw_map(g, now)
        if self.show_panel:
            self.draw_panel(g, W, H)
        if self.feed_h:
            self.draw_feed(g, W, H)
        self.draw_footer(g, W, H, now)
        return g

    def draw_header(self, g, W, wall):
        g.text(1, 0, "◉ ", "accent")
        g.text(3, 0, "THREATSCOPE", "bright")
        g.text(15, 0, " LIVE CYBER THREAT MAP", "dim")
        clock = datetime.fromtimestamp(wall).strftime("%a %d %b  %H:%M:%S ") + time.strftime("%Z")
        x = W - len(clock) - 1
        g.text(x, 0, clock, "dim")
        tags = []
        if self.paused:
            tags.append(("‖ PAUSED", "phishing"))
        mode = self.sim.mode
        if mode in ("log", "feed"):
            tags.append(("● LIVE", "exploit"))
        elif mode == "radar":
            tags.append(("● CLOUDFLARE RADAR", "exploit"))
        else:
            tags.append(("○ SIMULATED", "dim"))
        for t, a in tags:
            x -= len(t) + 3
            g.text(x, 0, t, a)
        for i in range(W):
            g.put(i, 1, "─", "faint")

    def draw_map(self, g, now):
        wm, sim = self.world, self.sim
        overlay = {}   # (cx, cy) -> [bits, prio, attr]
        labels = []

        def dot(px, py, attr, prio):
            ix, iy = int(px), int(py)
            if not (0 <= ix < wm.pw and 0 <= iy < wm.ph):
                return
            key = (ix >> 1, iy >> 2)
            bit = BRAILLE_BITS[(ix & 1, iy & 3)]
            e = overlay.get(key)
            if e is None:
                overlay[key] = [bit, prio, attr]
            else:
                e[0] |= bit
                if prio > e[1]:
                    e[1], e[2] = prio, attr

        def blob(px, py, attr, prio):
            for dx in (0, 1):
                for dy in (0, 1):
                    dot(px + dx - 0.5, py + dy - 0.5, attr, prio)

        def ease(u):
            return 1 - (1 - u) ** 2.2

        for a in sim.attacks:
            age = now - a.born
            bright, dim = a.kind, a.kind + "_dim"
            sx, sy = wm.project(*a.src)
            dx, dy = wm.project(*a.dst)
            dist = math.hypot(dx - sx, dy - sy)
            lift = min(dist * 0.42, wm.ph * 0.42)
            cx, cy = (sx + dx) / 2, (sy + dy) / 2 - lift

            tf = age / a.dur
            head = ease(min(1.0, tf))
            tail = ease(min(1.0, max(0.0, tf - Attack.TAIL)))
            if head > tail and dist > 1:
                n = max(3, int((head - tail) * (dist + lift) * 1.6))
                for i in range(n + 1):
                    u = tail + (head - tail) * i / n
                    v = 1 - u
                    px = v * v * sx + 2 * v * u * cx + u * u * dx
                    py = v * v * sy + 2 * v * u * cy + u * u * dy
                    frac = i / n
                    dot(px, py, bright if frac > 0.7 else dim, 2 if frac > 0.7 else 1)
                if tf < 1.0:
                    v, u = 1 - head, head
                    blob(v * v * sx + 2 * v * u * cx + u * u * dx,
                         v * v * sy + 2 * v * u * cy + u * u * dy, bright, 5)
            if age < 0.6:
                blob(sx, sy, bright if age < 0.3 else dim, 3)
            ra = (age - a.dur) / Attack.RIPPLE
            if 0 <= ra <= 1:
                for delay in (0.0, 0.25):
                    rr = ra - delay
                    if rr < 0:
                        continue
                    r = 1.2 + rr * 7.5
                    pts = max(8, int(2 * math.pi * r * 1.4))
                    att = bright if rr < 0.45 else dim
                    for k in range(pts):
                        th = 2 * math.pi * k / pts
                        dot(dx + r * math.cos(th), dy + r * math.sin(th), att, 4)
                blob(dx, dy, bright, 6)
                if ra < 0.85:
                    labels.append((int(dx) // 2 + 2, int(dy) // 4, a.dst_code[:3], bright))

        land_attr = "land" if self.map_style == "dots" else "land_solid"
        for cy in range(wm.rows):
            row = wm.cells[cy]
            for cx in range(wm.cols):
                e = overlay.get((cx, cy))
                if e:
                    g.put(self.map_x + cx, self.map_y + cy, chr(0x2800 | e[0]), e[2])
                elif row[cx]:
                    g.put(self.map_x + cx, self.map_y + cy, chr(0x2800 | row[cx]), land_attr)
        for lx, ly, txt, att in labels:
            if 0 <= lx and lx + len(txt) < wm.cols and 0 <= ly < wm.rows:
                g.text(self.map_x + lx, self.map_y + ly, txt, att)

        if not sim.attacks and sim.mode in ("log", "feed", "radar"):
            msg = {"log": "Waiting for attacks in the log…", "feed": "Waiting for events…",
                   "radar": "Fetching Cloudflare Radar data…"}[sim.mode]
            if sim.mode != "radar" or not sim.radar:
                g.text(self.map_x + max(0, (wm.cols - len(msg)) // 2), self.map_y + wm.rows - 1, msg, "dim")

    def bar(self, g, x, y, width, frac, attr):
        frac = max(0.0, min(1.0, frac))
        total = frac * width
        full = int(total)
        part = int((total - full) * 8)
        for i in range(width):
            if i < full:
                g.put(x + i, y, "█", attr)
            elif i == full and part:
                g.put(x + i, y, BAR_PARTIALS[part], attr)
            else:
                g.put(x + i, y, "·", "faint")

    def draw_panel(self, g, W, H):
        sim = self.sim
        px = W - self.PANEL_W - 1
        pw = self.PANEL_W
        bottom = H - 2 - (self.feed_h + 1 if self.feed_h else 0)
        for y in range(2, bottom + 1):
            g.put(px - 1, y, "│", "faint")
        y = 2
        avail = bottom - y
        (h_label, h_value, h_right), secs, types = sim.panel(max(3, min(8, avail - 13)))

        g.text(px + 1, y, h_label, "dim", maxw=pw - 1); y += 1
        g.text(px + 1, y, h_value, "accent")
        g.text(px + pw - len(h_right) - 1, y, h_right, "dim"); y += 2

        def section(title, rows, attr, max_rows):
            nonlocal y
            if y + 2 > bottom or max_rows <= 0:
                return
            g.text(px + 1, y, title, "bright"); y += 1
            if not rows:
                g.text(px + 1, y, "no data yet", "faint"); y += 2
                return
            top = max(f for _l, f in rows) or 1
            label_w = 17
            for label, frac in rows[:max_rows]:
                if y > bottom:
                    return
                g.text(px + 1, y, str(label)[:label_w - 1], "text")
                self.bar(g, px + 1 + label_w, y, pw - label_w - 7, frac / top, attr)
                s = f"{frac * 100:4.1f}%"
                g.text(px + pw - len(s), y, s, "dim")
                y += 1
            y += 1

        section(secs[0][0], secs[0][1], "accent", max(3, min(8, avail - 13)))

        if y + 4 <= bottom:
            g.text(px + 1, y, "ATTACK TYPES", "bright"); y += 1
            for k in TYPE_ORDER:
                if y > bottom:
                    break
                on = k in sim.enabled
                g.text(px + 1, y, "●", k if on else "off")
                g.text(px + 3, y, f"{sim.label(k):<12}"[:12], "text" if on else "off")
                self.bar(g, px + 16, y, pw - 23, types.get(k, 0), k if on else "off")
                s = f"{types.get(k, 0) * 100:4.1f}%"
                g.text(px + pw - len(s), y, s, "dim")
                y += 1
            y += 1

        section(secs[1][0], secs[1][1], "exploit_dim", max(0, bottom - y - 1))

    def draw_feed(self, g, W, H):
        sim = self.sim
        top = H - 1 - self.feed_h - 1
        for x in range(W):
            g.put(x, top, "─", "faint")
        g.text(2, top, " LIVE ATTACKS " if sim.mode != "radar" else " ATTACK PAIRS (SAMPLED FROM RADAR) ", "bright")
        cols = [("TIME", 10), ("TYPE", 14), ("ATTACK", 23), ("SOURCE", 22), ("", 3),
                ("TARGET", 22), (sim.detail_title(), 20)]
        x, y = 2, top + 1
        for name, w in cols:
            if x + w > W:
                break
            g.text(x, y, name, "dim")
            x += w
        for i, (ts, a) in enumerate(list(sim.feed)[: self.feed_h - 1]):
            y = top + 2 + i
            if y >= H - 1:
                break
            faded = i >= 4
            x = 2
            vals = [(ts, "dim"),
                    ("● " + sim.label(a.kind), a.kind if not faded else a.kind + "_dim"),
                    (a.name, "text" if not faded else "dim"),
                    (a.src_name, "text" if not faded else "dim"),
                    ("→", a.kind + "_dim"),
                    (a.dst_name, "bright" if not faded else "dim"),
                    (a.detail or "", "dim")]
            for (val, att), (_n, w) in zip(vals, cols):
                if x + w > W:
                    break
                g.text(x, y, val, att, maxw=w - 1)
                x += w

    def draw_footer(self, g, W, H, now):
        y = H - 1
        rate_desc = f"rate {self.sim.rate:g}/s" if self.sim.mode in ("demo", "radar") else "—"
        keys = [("q", "quit"), ("p", "pause"), ("+/-", rate_desc),
                ("1 2 3", "types"), ("m", "map"), ("c", "clear")]
        x = 1
        note = self.status if now < self.status_until else self.sim.source_note()
        limit = W - min(len(note), W // 2) - 3
        for k, d in keys:
            if x + len(k) + len(d) + 3 > limit:
                break
            g.text(x, y, k, "accent"); x += len(k) + 1
            g.text(x, y, d, "dim"); x += len(d) + 3
        note = note[: max(0, W - x - 2)]
        g.text(W - len(note) - 1, y, note, "phishing" if now < self.status_until else "faint")


# curses front-end
# --------------------------------------------------------------------------

def init_colors():
    attrs = {}
    if not curses.has_colors():
        for k, (_c, _c8, bold) in PALETTE.items():
            attrs[k] = curses.A_BOLD if bold else curses.A_NORMAL
        return attrs, curses.A_NORMAL
    curses.start_color()
    rich = curses.COLORS >= 256
    bg = BG256 if rich else curses.COLOR_BLACK
    for i, (k, (c256, c8, bold)) in enumerate(PALETTE.items(), start=1):
        curses.init_pair(i, c256 if rich else c8, bg)
        a = curses.color_pair(i)
        if bold and not rich:
            a |= curses.A_BOLD
        if k in ("bright", "accent") and rich:
            a |= curses.A_BOLD
        attrs[k] = a
    return attrs, attrs["base"]


class Engine:
    """Front-end independent loop state: input handling and simulation ticks."""

    def __init__(self, app, feed_q, reader):
        self.app, self.feed_q, self.reader = app, feed_q, reader
        self.sim_now = 0.0
        self.last = time.monotonic()

    def key(self, ch):
        """ch: a one-character string. Returns False to quit."""
        app, sim, now = self.app, self.app.sim, self.sim_now
        if ch in ("q", "Q", "\x1b", "\x03"):
            return False
        if ch in ("p", " "):
            app.paused = not app.paused
        elif ch in ("+", "="):
            sim.rate = min(40.0, round(sim.rate * 1.25 + 0.25, 1))
            app.flash(f"rate {sim.rate:g} arcs/s", now)
        elif ch in ("-", "_"):
            sim.rate = max(0.5, round(sim.rate / 1.25, 1))
            app.flash(f"rate {sim.rate:g} arcs/s", now)
        elif ch in ("1", "2", "3"):
            k = TYPE_ORDER[int(ch) - 1]
            sim.enabled ^= {k}
            app.flash(f"{sim.label(k)} {'on' if k in sim.enabled else 'off'}", now)
        elif ch in ("m", "M"):
            app.map_style = "solid" if app.map_style == "dots" else "dots"
        elif ch in ("c", "C") and sim.mode != "radar":
            sim.clear_stats()
            app.flash("stats cleared", now)
        return True

    def tick(self):
        app, sim, reader = self.app, self.app.sim, self.reader
        t0 = time.monotonic()
        dt = min(0.25, t0 - self.last)
        self.last = t0
        wall = time.time()
        if reader is not None:
            if reader.snapshot is not None:          # new Cloudflare Radar data
                sim.radar, reader.snapshot = reader.snapshot, None
                app.flash("Cloudflare Radar data updated", self.sim_now)
            if reader.error:
                app.flash(reader.error, self.sim_now, secs=8)
                reader.error = None
        if not app.paused:
            self.sim_now += dt
            while self.feed_q:
                ev = self.feed_q.popleft()
                src, dst = sim.resolve(ev.get("src")), sim.resolve(ev.get("dst"))
                if not src or not dst:
                    continue
                kind = str(ev.get("type", "malware")).lower()
                default = ATTACK_TYPES.get(kind, ATTACK_TYPES["malware"])["label"]
                extra = ev.get("industry")
                sim.add(src, dst, kind, str(ev.get("name", default)), extra,
                        ev.get("detail", extra), self.sim_now, wall)
            sim.step(self.sim_now, dt, wall)
        return wall


def run_curses(stdscr, engine, fps):
    curses.curs_set(0)
    stdscr.nodelay(True)
    attrs, base = init_colors()
    stdscr.bkgd(" ", base)
    frame = 1.0 / fps
    while True:
        t0 = time.monotonic()
        while True:
            ch = stdscr.getch()
            if ch == -1:
                break
            if ch == curses.KEY_RESIZE:
                curses.update_lines_cols()
            elif 0 <= ch < 256 and not engine.key(chr(ch)):
                return
        wall = engine.tick()
        H, W = stdscr.getmaxyx()
        g = engine.app.render(W, H, engine.sim_now, wall)
        stdscr.erase()
        for y in range(H):
            for x, s, a in g.runs(y):
                try:
                    stdscr.addstr(y, x, s, attrs.get(a, base))
                except curses.error:
                    pass   # bottom-right cell
        stdscr.noutrefresh()
        curses.doupdate()
        spent = time.monotonic() - t0
        if spent < frame:
            time.sleep(frame - spent)


# --------------------------------------------------------------------------
# Plain-ANSI front-end — used when curses isn't available (stock Windows
# Python). Needs a VT-capable console: Windows Terminal, or PowerShell /
# cmd on Windows 10+.
# --------------------------------------------------------------------------

def ansi_frame(g):
    out = []
    prev = None
    for y in range(g.h):
        out.append(f"\x1b[{y + 1};1H")
        for x, s, a in g.runs(y):
            if a != prev:
                c256, _c8, bold = PALETTE[a]
                out.append(f"\x1b[0;{'1;' if bold else ''}38;5;{c256};48;5;{BG256}m")
                prev = a
            out.append(s)
    return "".join(out)


def run_ansi(engine, fps):
    if os.name == "nt":
        import msvcrt
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k32.GetConsoleMode(h, ctypes.byref(mode)):
            k32.SetConsoleMode(h, mode.value | 0x0004)   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        k32.SetConsoleOutputCP(65001)

        def read_keys():
            keys = []
            while msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):   # arrow/function key prefix
                    msvcrt.getwch()
                    continue
                keys.append(ch)
            return keys
        restore = lambda: None
    else:
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setcbreak(fd)

        def read_keys():
            keys = []
            while select.select([sys.stdin], [], [], 0)[0]:
                keys.append(os.read(fd, 1).decode(errors="ignore"))
            return keys
        restore = lambda: termios.tcsetattr(fd, termios.TCSADRAIN, old)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    out = sys.stdout
    out.write("\x1b[?1049h\x1b[?25l\x1b[2J")
    frame = 1.0 / fps
    last_size = None
    try:
        while True:
            t0 = time.monotonic()
            if any(not engine.key(k) for k in read_keys()):
                return
            wall = engine.tick()
            size = os.get_terminal_size()
            W, H = size.columns, size.lines
            if (W, H) != last_size:
                out.write(f"\x1b[48;5;{BG256}m\x1b[2J")
                last_size = (W, H)
            # Leave the last column empty so consoles don't auto-wrap/scroll.
            g = engine.app.render(W - 1, H, engine.sim_now, wall)
            out.write(ansi_frame(g))
            out.flush()
            spent = time.monotonic() - t0
            if spent < frame:
                time.sleep(frame - spent)
    finally:
        out.write("\x1b[0m\x1b[?25h\x1b[?1049l")
        out.flush()
        restore()


# --------------------------------------------------------------------------
# Headless snapshot (ANSI) — handy for screenshots and CI
# --------------------------------------------------------------------------

def snapshot(app, W, H, seconds, fps=20):
    sim_now, wall = 0.0, time.time()
    dt = 1.0 / fps
    for _ in range(int(seconds * fps)):
        sim_now += dt
        wall += dt
        app.sim.step(sim_now, dt, wall)
    g = app.render(W, H, sim_now, wall)
    out = []
    for y in range(H):
        line = []
        for x, s, a in g.runs(y):
            c256, _c8, bold = PALETTE[a]
            line.append(f"\x1b[{'1;' if bold else ''}38;5;{c256};48;5;{BG256}m{s}")
        out.append("".join(line) + "\x1b[0m")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="Live cyber threat map for the terminal.",
        epilog="Data sources: (default) simulated · --radar real Cloudflare Radar attack statistics · "
               "--log live attacks from your own firewall/web/SSH log · --feed your own JSON events")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--radar", action="store_true",
                     help="real data: Cloudflare Radar layer-7 attack stats (needs CLOUDFLARE_API_TOKEN)")
    src.add_argument("--log", metavar="FILE",
                     help="live data: tail a Windows Firewall / nginx / Apache / SSH log and map the attackers")
    src.add_argument("--feed", metavar="FILE", help="tail a JSON-lines event file")
    ap.add_argument("--rate", type=float, default=3.5,
                    help="arcs per second for simulated and --radar modes (default 3.5)")
    ap.add_argument("--radar-interval", type=float, default=300,
                    help="seconds between Radar polls (minimum 60; default 300)")
    ap.add_argument("--radar-limit", type=int, default=20,
                    help="origin→target pairs to fetch from Radar (1-25; default 20)")
    ap.add_argument("--here", metavar="LAT,LON",
                    help="your location for --log (default: looked up from your public IP)")
    ap.add_argument("--log-replay", action="store_true",
                    help="with --log, also show what's already in the file, not just new lines")
    ap.add_argument("--log-all", action="store_true",
                    help="with --log, count every line with a public IP, not only recognised attacks")
    ap.add_argument("--map", choices=["dots", "solid"], default="dots", help="map style")
    ap.add_argument("--fps", type=int, default=24)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--ansi", action="store_true", help="force the plain-ANSI renderer (no curses)")
    ap.add_argument("--snapshot", metavar="WxH", help="render one simulated frame as ANSI text and exit")
    ap.add_argument("--warmup", type=float, default=6.0, help="seconds simulated before --snapshot")
    # "--here -29.8,31.0" would be read as a flag because of the minus sign.
    argv = sys.argv[1:]
    for i, a in enumerate(argv[:-1]):
        if a == "--here":
            argv[i:i + 2] = [f"--here={argv[i + 1]}"]
            break
    args = ap.parse_args(argv)

    if args.snapshot and (args.radar or args.log or args.feed):
        ap.error("--snapshot only works with simulated data")
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if args.radar and not token:
        ap.error("--radar needs a Cloudflare API token in CLOUDFLARE_API_TOKEN.\n"
                 "  Create one (free) at https://dash.cloudflare.com/profile/api-tokens with the\n"
                 "  'Radar: Read' permission, then in PowerShell:  $env:CLOUDFLARE_API_TOKEN=\"<token>\"")
    here = None
    if args.here:
        try:
            lat, lon = (float(v) for v in args.here.split(","))
            here = {"lat": lat, "lon": lon, "name": "You", "code": "YOU"}
        except ValueError:
            ap.error("--here expects LAT,LON, e.g. --here -29.86,31.02")
    for path in (args.log, args.feed):
        if path and not os.path.exists(path):
            hint = ""
            if args.log and path == args.log and "pfirewall" in path.lower():
                hint = ("\nTurn on Windows Firewall logging first (PowerShell as Administrator):\n"
                        "  Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384")
            sys.exit(f"file not found: {path}{hint}")

    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
    mode = "radar" if args.radar else "log" if args.log else "feed" if args.feed else "demo"
    sim = Sim(mode=mode, rate=args.rate, seed=args.seed)
    app = App(sim, map_style=args.map)

    if args.snapshot:
        W, H = (int(v) for v in args.snapshot.lower().split("x"))
        print(snapshot(app, W, H, args.warmup))
        return

    feed_q, reader = collections.deque(), None
    if args.radar:
        reader = RadarReader(token, args.radar_interval, args.radar_limit)
    elif args.log:
        reader = LogReader(args.log, feed_q, here, args.log_replay, args.log_all)
    elif args.feed:
        reader = FeedReader(args.feed, feed_q)
    if reader:
        reader.start()

    engine = Engine(app, feed_q, reader)
    try:
        if curses is not None and not args.ansi:
            os.environ.setdefault("ESCDELAY", "25")
            curses.wrapper(run_curses, engine, args.fps)
        else:
            run_ansi(engine, args.fps)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
