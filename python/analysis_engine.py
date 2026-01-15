#!/usr/bin/env python3

# Security Analysis Engine
# Detta script: 
# 1. Läser Linux JSON 
# 2. Läser Windows CSV 
# 3. Läser loggfiler med varningar och fel 
# 4. Klassificerar risker 
# 5. Genererar en rapport i TXT-format 

# ============================================================================
# IMPORTS
# ============================================================================
import json              # För att läsa Linux JSON-data
import csv               # För att läsa Windows CSV-data
from datetime import datetime  # För tidsstämplar i rapporten
from pathlib import Path      # För plattformsoberoende filsökvägar

# ============================================================================
# KONFIGURATION
# ============================================================================
# Bestäm var scriptets filer finns
SCRIPT_DIR = Path(__file__).parent          # python/ mappen
DATA_DIR = SCRIPT_DIR.parent / "data"       # data/ mappen (där input-filer finns)
REPORT_DIR = SCRIPT_DIR.parent / "report"   # report/ mappen (där rapporten sparas)

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
risks = {
    "critical": [],    # Akuta hot som kräver omedelbar åtgärd
    "high": [],        # Allvarliga hot som bör åtgärdas snabbt
    "medium": [],      # Måttliga hot som bör granskas
    "low": []          # Låga risker (används för framtida expansion)
}

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
        print(f"[WARN] Fil saknas: {LINUX_JSON}")
        return
    
    try:
        # Öppna och parsa JSON-filen
        with open(LINUX_JSON, 'r', encoding='utf-8') as f:
            linux_data = json.load(f)
        
        # Skriv ut sammanfattning av vad vi läst in
        process_count = len(linux_data.get('all_processes', []))
        anomaly_count = len(linux_data.get('anomalies', []))
        print(f"[INFO] Linux: {process_count} processer, {anomaly_count} anomalier")
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
        print(f"[WARN] Fil saknas: {WINDOWS_CSV}")
        return
    
    try:
        # Öppna och läs CSV-filen som en lista av dictionaries
        # Varje rad blir en dictionary där kolumnnamnen är nycklar
        with open(WINDOWS_CSV, 'r', encoding='utf-8') as f:
            windows_data = list(csv.DictReader(f))
        
        print(f"[INFO] Windows: {len(windows_data)} tjänster")
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
    print("[INFO] Läser loggar...")
    
    # Kontrollera om loggfilen finns
    if not ANOMALIES_LOG.exists():
        print(f"[WARN] Fil saknas: {ANOMALIES_LOG}")
        return
    
    try:
        # Läs alla rader och ta bort tomma rader
        with open(ANOMALIES_LOG, 'r', encoding='utf-8') as f:
            anomalies_data = [line.strip() for line in f if line.strip()]
        
        # Räkna antal varningar och fel för statistik
        warn = sum(1 for line in anomalies_data if '[WARN]' in line)
        error = sum(1 for line in anomalies_data if '[ERROR]' in line)
        print(f"[INFO] Loggar: {len(anomalies_data)} rader, {warn} varningar, {error} fel")
    except Exception as e:
        print(f"[ERROR] Kunde inte läsa loggar: {e}")

# ============================================================================
# RISKKLASSIFICERING - Analysera och kategorisera hot
# ============================================================================

def classify_risks():
    """
    Klassificerar alla risker från Linux, Windows och loggar.
    
    Klassificeringsnivåer:
    - CRITICAL: Akuta hot som kräver omedelbar åtgärd (t.ex. reverse shells, miners)
    - HIGH: Allvarliga risker (riskiga processer/tjänster som körs)
    - MEDIUM: Måttliga risker (varningar, icke-kritiska avvikelser)
    - LOW: Låga risker (framtida användning)
    """
    print("[INFO] Klassificerar risker...")
    
    # ========================================
    # STEG 1: Klassificera Linux-processer
    # ========================================
    # Gå igenom alla anomalier (riskabla processer) från Linux-skriptet
    for anomaly in linux_data.get('anomalies', []):
        cmd = anomaly.get('command', '').lower()
        
        # Identifiera KRITISKA hot baserat på kommando-mönster
        # Dessa mönster indikerar aktiv attack eller malware:
        # - 'nc -l': Netcat listener (kan användas för reverse shell)
        # - '/dev/tcp': Bash TCP-anslutning (ofta använd för backdoors)
        # - 'bash -i': Interaktiv bash-session (typiskt för reverse shells)
        # - 'xmrig': Cryptocurrency miner (malware)
        critical_patterns = ['nc -l', '/dev/tcp', 'bash -i', 'xmrig']
        level = "critical" if any(p in cmd for p in critical_patterns) else "high"
        
        # Lägg till i rätt risknivå
        risks[level].append({
            "type": "Linux Process",
            "name": f"PID {anomaly.get('pid')}",
            "details": anomaly.get('command', '')[:80],  # Begränsa längd för läsbarhet
            "pattern": anomaly.get('matched_pattern', '')
        })
    
    # ========================================
    # STEG 2: Klassificera Windows-tjänster
    # ========================================
    # Först: Extrahera vilka tjänster som flaggats som riskabla från loggen
    risky_services = set()  # Använd set för att undvika dubbletter
    for line in anomalies_data:
        # Leta efter lograder som rapporterar riskiga tjänster
        if '[WARN]' in line and 'Riskig tjänst:' in line:
            try:
                # Parsa ut tjänstnamnet från loggraden
                # Format: "[timestamp] [WARN] Riskig tjänst: ServiceName (Mönster: pattern)"
                service_name = line.split('Riskig tjänst:')[1].split('(')[0].strip()
                risky_services.add(service_name)
            except:
                # Ignorera felaktigt formaterade rader
                pass
    
    # Sedan: Kolla Windows-tjänster och flagga de som är både riskabla OCH körande
    for service in windows_data:
        name = service.get('Name', '')
        # En riskig tjänst som faktiskt körs är en HIGH risk
        if name in risky_services and service.get('Status') == 'Running':
            risks['high'].append({
                "type": "Windows Service",
                "name": name,
                "details": service.get('DisplayName', ''),
                "pattern": "Running risky service"
            })
    
    # ========================================
    # STEG 3: Klassificera logghändelser
    # ========================================
    # Analysera alla loggrader och kategorisera dem
    for line in anomalies_data:
        if '[ERROR]' in line:
            # Fel är HIGH risk - något har gått fel under skanning
            risks['high'].append({
                "type": "Log Error",
                "name": "Error Event",
                "details": line[:80],  # Begränsa längd
                "pattern": ""
            })
        elif '[WARN]' in line:
            # Varningar är MEDIUM risk - något misstänkt har upptäckts
            risks['medium'].append({
                "type": "Log Warning",
                "name": "Warning Event",
                "details": line[:80],
                "pattern": ""
            })
    
    # Skriv ut sammanfattning av klassificeringen
    print(f"[INFO] Risker: {len(risks['critical'])} critical, {len(risks['high'])} high, {len(risks['medium'])} medium")

# ============================================================================
# RAPPORTGENERERING - Skapa läsbar säkerhetsrapport
# ============================================================================

def generate_report():
    """
    Genererar slutrapport i TXT-format.
    
    Rapporten innehåller:
    - Sammanfattning av skanning
    - Totala säkerhetsnivån (CRITICAL/HIGH/MEDIUM/LOW)
    - Lista över kritiska, höga och medium risker
    - Rekommendationer för åtgärder
    """
    print("[INFO] Genererar säkerhetsrapport...")
    
    # Skapa report-mappen om den inte finns
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Skapa tidsstämplar för rapporten
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Läsbar tidsstämpel
    report_file = REPORT_DIR / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"  # Filnamn
    
    # ========================================
    # Beräkna totalrisk för hela systemet
    # ========================================
    critical_count = len(risks['critical'])
    high_count = len(risks['high'])
    medium_count = len(risks['medium'])
    
    # Bestäm övergripande säkerhetsnivå baserat på antal hot:
    # - Finns NÅGON critical risk → CRITICAL
    # - Fler än 5 high risks → HIGH
    # - Fler än 10 medium risks → MEDIUM
    # - Annars → LOW
    overall_severity = "LOW"
    if critical_count > 0:
        overall_severity = "CRITICAL"
    elif high_count > 5:
        overall_severity = "HIGH"
    elif medium_count > 10:
        overall_severity = "MEDIUM"
    
    # ========================================
    # Bygg rapport som en lista av textrader
    # ========================================
    report_lines = []
    
    # Header
    report_lines.append("=" * 70)
    report_lines.append("SÄKERHETSRAPPORT")
    report_lines.append("=" * 70)
    report_lines.append(f"Genererad: {timestamp}")
    report_lines.append(f"Total säkerhetsnivå: {overall_severity}")
    report_lines.append("")
    
    # Sammanfattning av skanningen
    report_lines.append("SAMMANFATTNING")
    report_lines.append("-" * 70)
    report_lines.append(f"Linux processer: {len(linux_data.get('all_processes', []))} totalt, {len(linux_data.get('anomalies', []))} anomalier")
    report_lines.append(f"Windows tjänster: {len(windows_data)} totalt")
    report_lines.append(f"Logghändelser: {len(anomalies_data)} rader")
    report_lines.append(f"")
    report_lines.append(f"Risker: {critical_count} CRITICAL | {high_count} HIGH | {medium_count} MEDIUM")
    report_lines.append("")
    
    # ========================================
    # Sektion 1: Kritiska risker
    # ========================================
    # Visa alla CRITICAL hot - dessa kräver omedelbar åtgärd
    if critical_count > 0:
        report_lines.append("KRITISKA RISKER")
        report_lines.append("-" * 70)
        for risk in risks['critical']:
            # Visa typ av hot (Linux Process, Windows Service, etc.)
            report_lines.append(f"[{risk['type']}] {risk['name']}")
            # Visa detaljer (kommando, tjänstnamn, etc.)
            report_lines.append(f"  Details: {risk['details']}")
            # Visa vilket mönster som matchade (från risklistan)
            if risk['pattern']:
                report_lines.append(f"  Pattern: {risk['pattern']}")
            report_lines.append("")
    
    # ========================================
    # Sektion 2: Höga risker
    # ========================================
    # Visa HIGH hot - begränsa till max 20 för att inte överbelasta rapporten
    if high_count > 0:
        report_lines.append("HÖGA RISKER")
        report_lines.append("-" * 70)
        for risk in risks['high'][:20]:  # Max 20 för att hålla rapporten läsbar
            report_lines.append(f"[{risk['type']}] {risk['name']}")
            report_lines.append(f"  Details: {risk['details']}")
            if risk['pattern']:
                report_lines.append(f"  Pattern: {risk['pattern']}")
            report_lines.append("")
    
    # ========================================
    # Sektion 3: Medium risker
    # ========================================
    # Visa ALLA medium risker (ofta varningar från loggar)
    if medium_count > 0:
        report_lines.append("MEDIUM RISKER")
        report_lines.append("-" * 70)
        for risk in risks['medium']:
            report_lines.append(f"[{risk['type']}] {risk['name']}")
            report_lines.append(f"  Details: {risk['details']}")
            if risk['pattern']:
                report_lines.append(f"  Pattern: {risk['pattern']}")
            report_lines.append("")
    
    # ========================================
    # Sektion 4: Rekommendationer
    # ========================================
    # Ge användbara råd baserat på vad som upptäckts
    report_lines.append("REKOMMENDATIONER")
    report_lines.append("-" * 70)
    
    # Dynamiska rekommendationer baserat på risknivåer
    if critical_count > 0:
        report_lines.append("- KRITISKT: Omedelbar åtgärd krävs!")
    if high_count > 5:
        report_lines.append("- Undersök och åtgärda högrisk-processer och tjänster")
    if medium_count > 10:
        report_lines.append("- Granska mediumrisk-händelser vid tillfälle")
    
    # Allmänna säkerhetsråd (visas alltid)
    report_lines.append("- Kör säkerhetsskanning regelbundet")
    report_lines.append("- Uppdatera risklistan baserat på nya hot")
    report_lines.append("- Håll system och tjänster uppdaterade")
    report_lines.append("")
    report_lines.append("=" * 70)
    
    # ========================================
    # Spara rapporten till fil
    # ========================================
    try:
        # Skriv alla textrader till filen
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        # Bekräfta att rapporten skapats
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
    2. Klassificera alla risker i lämpliga kategorier
    3. Generera en läsbar textrapport med resultat och rekommendationer
    """
    print("=" * 60)
    print("Security Analysis Engine")
    print("=" * 60)
    
    # Steg 1: Datainläsning
    load_linux()        # Läs Linux-processdata från JSON
    load_windows()      # Läs Windows-tjänstedata från CSV
    load_anomalies()    # Läs loggfiler med varningar och fel
    
    # Steg 2: Analys och klassificering
    classify_risks()    # Analysera och kategorisera alla hot
    
    # Steg 3: Rapportgenerering
    generate_report()   # Skapa och spara slutrapporten
    
    print("=" * 60)
    print("Analys slutförd!")
    print("=" * 60)

# ============================================================================
# PROGRAMSTART
# ============================================================================
# Detta körs endast om scriptet körs direkt (inte importeras som modul)
if __name__ == "__main__":
    main()
