#!/usr/bin/env python3
# ============================================================================
# Security Analysis Engine - Advanced Version (HTML Rapport)
# ============================================================================
# Detta script:
# 1. Läser Linux JSON, Windows CSV och anomalies.log
# 2. Klassificerar risker i olika nivåer (CRITICAL/HIGH/MEDIUM/LOW)
# 3. Genererar en avancerad HTML-rapport med styling och tabeller
# ============================================================================

# ============================================================================
# IMPORT
# ============================================================================
import json              # För att läsa Linux JSON-data
import csv               # För att läsa Windows CSV-data
import os                # För operativsystem-funktioner (filhantering)
from datetime import datetime  # För tidsstämplar i rapporten
from pathlib import Path      # För plattformsoberoende filsökvägar

# ============================================================================
# KONFIGURATION
# ============================================================================
# Bestäm var scriptets filer finns
SCRIPT_DIR = Path(__file__).parent          # python/ mappen
DATA_DIR = SCRIPT_DIR.parent / "data"       # data/ mappen (där input-filer finns)
REPORT_DIR = SCRIPT_DIR.parent / "report"   # report/ mappen (där HTML-rapporten sparas)

# Definiera sökvägar till input-filer
LINUX_JSON = DATA_DIR / "linux_output.json"      # JSON från Linux-skript
WINDOWS_CSV = DATA_DIR / "windows_output.csv"    # CSV från Windows-skript
ANOMALIES_LOG = DATA_DIR / "anomalies.log"       # Loggfil med alla varningar/fel

# ============================================================================
# GLOBALA DATASTRUKTURER
# ============================================================================
# Dessa variabler håller all inläst och analyserad data
linux_data = {}        # Dictionary med Linux-processdata från JSON
windows_data = []      # Lista med Windows-tjänster från CSV
anomalies_data = []    # Lista med loggrader från anomalies.log

# Klassificerade risker - varje nivå innehåller en lista med hot-objekt
# Tre separata kategorier för processer, tjänster och händelser
classified_processes = {"critical": [], "high": [], "medium": [], "low": []}  # Linux-processer
classified_services = {"critical": [], "high": [], "medium": [], "low": []}   # Windows-tjänster
classified_events = {"critical": [], "high": [], "medium": [], "low": []}     # Logghändelser

# ============================================================================
# DATAINLÄSNING - Läs in data från olika källor
# ============================================================================

def load_linux():
    """
    Läser Linux JSON-output från bash-scriptet.
    
    JSON-filen innehåller:
    - all_processes: Lista med alla körande processer (PID, user, CPU, minne, kommando)
    - anomalies: Lista med upptäckta riskabla processer som matchat risklistan
    - metadata: Skanningstid, hostname, severity-nivå
    """
    global linux_data
    
    print("[INFO] Läser Linux JSON...")
    
    # Kontrollera om filen finns innan vi försöker läsa den
    if not LINUX_JSON.exists():
        print(f"[WARN] Linux JSON existerar inte: {LINUX_JSON}")
        return
    
    try:
        # Öppna och parsa JSON-filen
        with open(LINUX_JSON, 'r', encoding='utf-8') as f:
            linux_data = json.load(f)
        
        # Räkna och visa statistik om vad vi läst in
        process_count = len(linux_data.get('all_processes', []))
        risky_count = len(linux_data.get('anomalies', []))
        
        print(f"[INFO] Linux data läst: {process_count} processer, {risky_count} anomalier")
    except Exception as e:
        print(f"[ERROR] Kunde inte läsa Linux JSON: {e}")

def load_windows():
    """
    Läser Windows CSV-output från PowerShell-scriptet.
    
    CSV-filen innehåller kolumner:
    - Name: Tjänstens systemnamn (t.ex. 'wuauserv')
    - DisplayName: Tjänstens visningsnamn (t.ex. 'Windows Update')
    - Status: Tjänstens status (Running, Stopped, etc.)
    """
    global windows_data
    
    print("[INFO] Läser Windows CSV...")
    
    # Kontrollera om filen finns
    if not WINDOWS_CSV.exists():
        print(f"[WARN] Windows CSV existerar inte: {WINDOWS_CSV}")
        return
    
    try:
        # Öppna och läs CSV-filen som en lista av dictionaries
        # csv.DictReader gör varje rad till en dictionary där kolumnnamnen är nycklar
        with open(WINDOWS_CSV, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            windows_data = list(reader)
        
        print(f"[INFO] Windows data läst: {len(windows_data)} tjänster")
    except Exception as e:
        print(f"[ERROR] Kunde inte läsa Windows CSV: {e}")

def load_anomalies():
    """
    Läser anomalies.log och eventuella andra loggfiler.
    
    Loggfilen innehåller tidsstämplade händelser från båda scripten:
    - [INFO]: Informativa meddelanden om skriptets körning
    - [WARN]: Varningar om upptäckta risker (riskiga processer/tjänster)
    - [ERROR]: Fel som uppstått under körning
    
    Denna funktion kan utökas för att läsa flera loggfiler vid behov.
    """
    global anomalies_data
    
    print("[INFO] Läser anomalies.log...")
    
    # Kontrollera om loggfilen finns
    if not ANOMALIES_LOG.exists():
        print(f"[WARN] Anomalies log existerar inte: {ANOMALIES_LOG}")
        return
    
    try:
        # Läs alla rader från loggfilen
        with open(ANOMALIES_LOG, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Parsa loggraderna - ta bort tomma rader och whitespace
        for line in lines:
            line = line.strip()
            if line:  # Skippa tomma rader
                anomalies_data.append(line)
        
        # Räkna antal varningar och fel för statistik
        warn_count = sum(1 for line in anomalies_data if '[WARN]' in line)
        error_count = sum(1 for line in anomalies_data if '[ERROR]' in line)
        
        print(f"[INFO] Anomalies log läst: {len(anomalies_data)} rader, {warn_count} varningar, {error_count} fel")
    except Exception as e:
        print(f"[ERROR] Kunde inte läsa anomalies log: {e}")

# ============================================================================
# RISKKLASSIFICERING - Analysera och kategorisera hot
# ============================================================================

def classify_processes():
    """
    Klassificerar Linux-processer efter riskgrad.
    
    Klassificeringsnivåer:
    - CRITICAL: Akuta hot som kräver omedelbar åtgärd (t.ex. reverse shells, miners)
    - HIGH: Allvarliga risker (riskiga processer som matchar risklistan)
    - LOW: Normala processer utan risker
    """
    print("[INFO] Klassificerar processer...")
    
    # Hämta alla processer och anomalier från Linux-datan
    all_processes = linux_data.get('all_processes', [])
    anomalies = linux_data.get('anomalies', [])
    
    # ========================================
    # STEG 1: Klassificera anomalier (riskiga processer)
    # ========================================
    for anomaly in anomalies:
        # Börja med att anta HIGH risk som standard
        risk_level = "high"
        
        # Identifiera KRITISKA hot baserat på kommando-mönster
        # Dessa mönster indikerar aktiv attack eller malware:
        # - 'nc -l': Netcat listener (kan användas för reverse shell)
        # - '/dev/tcp': Bash TCP-anslutning (ofta använd för backdoors)
        # - 'bash -i': Interaktiv bash-session (typiskt för reverse shells)
        # - 'xmrig': Cryptocurrency miner (malware)
        critical_patterns = ['nc -l', '/dev/tcp', 'bash -i', 'xmrig']
        if any(pattern in anomaly.get('command', '').lower() for pattern in critical_patterns):
            risk_level = "critical"
        
        # Lägg till i rätt risknivå med all relevant information
        classified_processes[risk_level].append({
            "pid": anomaly.get('pid'),
            "command": anomaly.get('command', ''),
            "pattern": anomaly.get('matched_pattern', ''),
            "risk": risk_level.upper()
        })
    
    # ========================================
    # STEG 2: Klassificera normala processer som LOW risk
    # ========================================
    for proc in all_processes:
        # Kontrollera om denna process redan klassificerats som en anomali
        # Om den redan finns i high eller critical, skippa den
        already_classified = any(
            p['pid'] == proc.get('pid') 
            for p in classified_processes['high'] + classified_processes['critical']
        )
        
        if not already_classified:
            # Detta är en normal, säker process
            classified_processes['low'].append({
                "pid": proc.get('pid'),
                "command": proc.get('command', '')[:50],  # Begränsa längd för läsbarhet
                "risk": "LOW"
            })
    
    # Skriv ut sammanfattning
    critical_count = len(classified_processes['critical'])
    high_count = len(classified_processes['high'])
    
    print(f"[INFO] Processer klassificerade: {critical_count} critical, {high_count} high")

def classify_services():
    """
    Klassificerar Windows-tjänster efter riskgrad.
    
    Klassificeringsnivåer:
    - HIGH: Riskiga tjänster som faktiskt körs (Running)
    - MEDIUM: Riskiga tjänster som är stoppade
    - LOW: Säkra tjänster
    """
    print("[INFO] Klassificerar tjänster...")
    
    # ========================================
    # STEG 1: Extrahera riskiga tjänster från loggen
    # ========================================
    # Hitta vilka tjänster som PowerShell-scriptet flaggat som riskiga
    risky_services = set()  # Använd set för att undvika dubbletter
    
    for line in anomalies_data:
        # Leta efter loggraderna som rapporterar riskiga tjänster
        if '[WARN]' in line and 'Riskig tjänst:' in line:
            # Parsa ut tjänstnamnet från loggraden
            # Format: "[timestamp] [WARN] Riskig tjänst: ServiceName - Mönster: pattern"
            try:
                service_name = line.split('Riskig tjänst:')[1].split('-')[0].strip()
                risky_services.add(service_name)
            except:
                # Ignorera felaktigt formaterade loggr ader
                pass
    
    # ========================================
    # STEG 2: Klassificera alla Windows-tjänster
    # ========================================
    for service in windows_data:
        service_name = service.get('Name', '')
        status = service.get('Status', '')
        
        # Kontrollera om denna tjänst är flaggad som riskig
        if service_name in risky_services:
            # En riskig tjänst som KÖRS är en HIGH risk
            if status == 'Running':
                classified_services['high'].append({
                    "name": service_name,
                    "display_name": service.get('DisplayName', ''),
                    "status": status,
                    "risk": "HIGH"
                })
            else:
                # En riskig tjänst som är STOPPAD är en MEDIUM risk
                classified_services['medium'].append({
                    "name": service_name,
                    "display_name": service.get('DisplayName', ''),
                    "status": status,
                    "risk": "MEDIUM"
                })
        else:
            # Denna tjänst är inte flaggad som riskig = LOW risk
            classified_services['low'].append({
                "name": service_name,
                "display_name": service.get('DisplayName', ''),
                "status": status,
                "risk": "LOW"
            })
    
    # Skriv ut sammanfattning
    high_count = len(classified_services['high'])
    medium_count = len(classified_services['medium'])
    
    print(f"[INFO] Tjänster klassificerade: {high_count} high, {medium_count} medium")

def classify_ip_events():
    """
    Klassificerar händelser från anomalies.log baserat på loggnivå.
    
    Klassificeringsnivåer:
    - HIGH: ERROR-händelser (något gick fel under skanning)
    - MEDIUM: WARN-händelser (varningar om upptäckta risker)
    - LOW: INFO-händelser (informativa meddelanden)
    """
    print("[INFO] Klassificerar händelser från log...")
    
    # Loopa igenom alla loggrader och klassificera baserat på nivå
    for line in anomalies_data:
        # Extrahera tidsstämpel från början av loggraden
        # Format: [YYYY-MM-DD HH:MM:SS] [LEVEL] message
        try:
            timestamp = line.split(']')[0].replace('[', '')
        except:
            timestamp = "Unknown"
        
        # Klassificera baserat på loggnivå
        if '[ERROR]' in line:
            # ERROR = HIGH risk - något gick fel under skanning
            classified_events['high'].append({
                "timestamp": timestamp,
                "message": line,
                "risk": "HIGH"
            })
        elif '[WARN]' in line:
            # WARN = MEDIUM risk - varning om upptäckt risk
            classified_events['medium'].append({
                "timestamp": timestamp,
                "message": line,
                "risk": "MEDIUM"
            })
        elif '[INFO]' in line:
            # INFO = LOW risk - informativt meddelande
            classified_events['low'].append({
                "timestamp": timestamp,
                "message": line,
                "risk": "LOW"
            })
    
    # Skriv ut sammanfattning
    high_count = len(classified_events['high'])
    medium_count = len(classified_events['medium'])
    
    print(f"[INFO] Händelser klassificerade: {high_count} high, {medium_count} medium")

# ============================================================================
# RAPPORTGENERERING - Skapa avancerad HTML-rapport
# ============================================================================

def generate_report():
    """
    Genererar slutrapport i HTML-format med styling och tabeller.
    
    Rapporten innehåller:
    - Sammanfattning med visuella boxar för varje risknivå
    - Metadata om skanning
    - Tabeller med kritiska processer, högrisk-tjänster och viktiga händelser
    - Dynamiska rekommendationer baserat på upptäckta risker
    """
    print("[INFO] Genererar säkerhetsrapport...")
    
    # Skapa report-mappen om den inte finns
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Skapa tidsstämplar för rapporten
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Läsbar tidsstämpel
    report_file = REPORT_DIR / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"  # Filnamn
    
    # ========================================
    # Beräkna totalrisker för hela systemet
    # ========================================
    # Summera risker från alla tre kategorier (processer, tjänster, händelser)
    critical_total = len(classified_processes['critical']) + len(classified_services['critical'])
    high_total = len(classified_processes['high']) + len(classified_services['high']) + len(classified_events['high'])
    medium_total = len(classified_processes['medium']) + len(classified_services['medium']) + len(classified_events['medium'])
    
    # Bestäm övergripande säkerhetsnivå baserat på antal hot:
    # - Finns NÅGON critical risk → CRITICAL
    # - Fler än 5 high risks → HIGH
    # - Fler än 10 medium risks → MEDIUM
    # - Annars → LOW
    overall_severity = "LOW"
    if critical_total > 0:
        overall_severity = "CRITICAL"
    elif high_total > 5:
        overall_severity = "HIGH"
    elif medium_total > 10:
        overall_severity = "MEDIUM"
    
    # HTML-rapport
    html_content = f"""
<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Säkerhetsrapport - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .summary-box {{ padding: 20px; border-radius: 5px; text-align: center; }}
        .critical {{ background-color: #dc3545; color: white; }}
        .high {{ background-color: #fd7e14; color: white; }}
        .medium {{ background-color: #ffc107; color: black; }}
        .low {{ background-color: #28a745; color: white; }}
        .severity-badge {{ display: inline-block; padding: 5px 15px; border-radius: 3px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #007bff; color: white; }}
        tr:hover {{ background-color: #f1f1f1; }}
        .timestamp {{ color: #888; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Säkerhetsrapport</h1>
        <p class="timestamp">Genererad: {timestamp}</p>
        
        <div class="summary">
            <div class="summary-box critical">
                <h3>{critical_total}</h3>
                <p>CRITICAL</p>
            </div>
            <div class="summary-box high">
                <h3>{high_total}</h3>
                <p>HIGH</p>
            </div>
            <div class="summary-box medium">
                <h3>{medium_total}</h3>
                <p>MEDIUM</p>
            </div>
            <div class="summary-box low">
                <h3>{len(classified_processes['low']) + len(classified_services['low'])}</h3>
                <p>LOW</p>
            </div>
        </div>
        
        <h2>📊 Sammanfattning</h2>
        <p><strong>Total säkerhetsnivå:</strong> <span class="severity-badge {overall_severity.lower()}">{overall_severity}</span></p>
        <p><strong>Linux processer:</strong> {len(linux_data.get('all_processes', []))} totalt, {len(linux_data.get('anomalies', []))} anomalier</p>
        <p><strong>Windows tjänster:</strong> {len(windows_data)} totalt, {high_total} riskiga</p>
        <p><strong>Loggade händelser:</strong> {len(anomalies_data)} rader</p>
        
        <h2>⚠️ Kritiska processer (Linux)</h2>
        <table>
            <tr><th>PID</th><th>Kommando</th><th>Mönster</th><th>Risk</th></tr>
"""
    
    # Lägg till kritiska processer
    if classified_processes['critical']:
        for proc in classified_processes['critical']:
            html_content += f"""
            <tr>
                <td>{proc['pid']}</td>
                <td>{proc['command'][:80]}</td>
                <td>{proc['pattern']}</td>
                <td><span class="severity-badge critical">{proc['risk']}</span></td>
            </tr>
"""
    else:
        html_content += '<tr><td colspan="4" style="text-align:center;">Inga kritiska processer funna ✅</td></tr>'
    
    html_content += """
        </table>
        
        <h2>🔴 Högrisk-tjänster (Windows)</h2>
        <table>
            <tr><th>Tjänst</th><th>Visningsnamn</th><th>Status</th><th>Risk</th></tr>
"""
    
    # Lägg till högrisk-tjänster
    if classified_services['high']:
        for service in classified_services['high']:
            html_content += f"""
            <tr>
                <td>{service['name']}</td>
                <td>{service['display_name']}</td>
                <td>{service['status']}</td>
                <td><span class="severity-badge high">{service['risk']}</span></td>
            </tr>
"""
    else:
        html_content += '<tr><td colspan="4" style="text-align:center;">Inga högrisk-tjänster funna ✅</td></tr>'
    
    html_content += """
        </table>
        
        <h2>📋 Viktiga händelser</h2>
        <table>
            <tr><th>Tidsstämpel</th><th>Meddelande</th><th>Risk</th></tr>
"""
    
    # Lägg till viktiga händelser (max 20)
    important_events = classified_events['high'][:10] + classified_events['medium'][:10]
    if important_events:
        for event in important_events:
            html_content += f"""
            <tr>
                <td>{event['timestamp']}</td>
                <td>{event['message'][:100]}</td>
                <td><span class="severity-badge {event['risk'].lower()}">{event['risk']}</span></td>
            </tr>
"""
    else:
        html_content += '<tr><td colspan="3" style="text-align:center;">Inga viktiga händelser ✅</td></tr>'
    
    html_content += """
        </table>
        
        <h2>✅ Rekommendationer</h2>
        <ul>
"""
    
    # Generera rekommendationer
    if critical_total > 0:
        html_content += '<li>⚠️ <strong>KRITISKT:</strong> Omedelbar åtgärd krävs - kritiska hot detekterade!</li>'
    if high_total > 5:
        html_content += '<li>🔴 Undersök och åtgärda högrisk-processer och tjänster</li>'
    if medium_total > 10:
        html_content += '<li>🟡 Granska mediumrisk-händelser vid tillfälle</li>'
    
    html_content += """
            <li>🔒 Kör säkerhetsskanning regelbundet (dagligen rekommenderas)</li>
            <li>📊 Uppdatera risklistan baserat på nya hot</li>
            <li>🛡️ Håll system och tjänster uppdaterade</li>
        </ul>
    </div>
</body>
</html>
"""
    
    # Spara rapporten
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[INFO] Rapport sparad: {report_file}")
        print(f"[INFO] Total säkerhetsnivå: {overall_severity}")
    except Exception as e:
        print(f"[ERROR] Kunde inte spara rapport: {e}")

# ============================================================================
# HUVUDPROGRAM
# ============================================================================

def main():
    """
    Huvudfunktionen som orchestrerar hela analysprocessen.
    
    Arbetsflöde:
    1. Läs in data från Linux JSON, Windows CSV och loggar
    2. Klassificera alla risker i lämpliga kategorier (processer, tjänster, händelser)
    3. Generera en avancerad HTML-rapport med resultat och rekommendationer
    """
    print("=" * 60)
    print("Security Analysis Engine - Advanced (HTML)")
    print("=" * 60)
    
    # ========================================
    # STEG 1: Datainläsning
    # ========================================
    load_linux()        # Läs Linux-processdata från JSON
    load_windows()      # Läs Windows-tjänstedata från CSV
    load_anomalies()    # Läs loggfiler med varningar och fel
    
    # ========================================
    # STEG 2: Analys och klassificering
    # ========================================
    classify_processes()    # Klassificera Linux-processer efter risknivå
    classify_services()     # Klassificera Windows-tjänster efter risknivå
    classify_ip_events()    # Klassificera logghändelser efter risknivå
    
    # ========================================
    # STEG 3: Rapportgenerering
    # ========================================
    generate_report()   # Skapa och spara HTML-rapporten
    
    print("=" * 60)
    print("Analys slutförd!")
    print("=" * 60)

# ============================================================================
# PROGRAMSTART
# ============================================================================
# Detta körs endast om scriptet körs direkt (inte importeras som modul)
if __name__ == "__main__":
    main()
