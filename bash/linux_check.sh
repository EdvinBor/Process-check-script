#!/bin/bash

# ============================================================================
# Linux Process Security Check Script
# ============================================================================
# Detta script:
# 1. Hämtar alla aktiva processer från systemet
# 2. Jämför processkommandona mot en risklista
# 3. Genererar en JSON-fil med resultat
# 4. Loggar alla upptäckta risker
# ============================================================================

# set -o pipefail: Om något kommando i en pipe misslyckas, misslyckas hela pipelinen
set -o pipefail

# ============================================================================
# KONFIGURATION
# ============================================================================
# Definiera sökvägar till in och utfiler
output="../data/linux_output.json"          # Utfil: JSON med resultat
logfile="../data/anomalies.log"            # Loggfil: alla händelser och varningar
risklist="../data/risklist.txt"            # Indata: lista med riskabla processmönster

# ============================================================================
# GLOBALA VARIABLER
# ============================================================================
# Arrays för att lagra data under körning
anomalies=()           # Ska innehålla upptäckta riskiga processer
all_processes=()       # Ska innehålla ALLA processer från systemet
total_processes=0     # Räknare för totalt antal processer
risky_processes=0     # Räknare för antal riskiga processer funna

# ============================================================================
# LOGGNING OCH FELHANTERING
# ============================================================================

# Funktion: log()
# Syfte: Skriver loggmeddelanden till både console och loggfil
# Parametrar:
#   $1 = Nivå (INFO, WARN, ERROR)
#   $2 = Meddelande
log() {
    # Skapa tidsstämpel i format: YYYY-MM-DD HH:MM:SS
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Skriv ut loggmeddelande med format: [timestamp] [level] message
    # tee -a: skriv både till stdout OCH append till logfil
    # >&2: omdirigera till stderr (för att synliggöra felmeddelanden)
    echo "[$timestamp] [$1] $2" | tee -a "$logfile" >&2
}

# Funktion: error_exit()
# Syfte: Logga ett fel och avsluta scriptet
# Parametrar:
#   $1 = Felmeddelande
error_exit() {
    log "ERROR" "$1"
    exit 1  # Avsluta med felkod 1
}

# ============================================================================
# FILKONTROLL
# ============================================================================

# Funktion: check_files()
# Syfte: Verifiera att alla nödvändiga filer och mappar finns innan körning
# Denna funktion säkerställer att:
#   1. Risklistan existerar (vi behöver den för att jämföra)
#   2. Output-mappen existerar (vi behöver kunna skriva resultat)
check_files() {
    # Kontrollera att risklistan existerar
    # [[ ! -f "$risklist" ]] = om filen INTE existerar
    [[ ! -f "$risklist" ]] && error_exit "Risklistan saknas: $risklist"
    
    # Kontrollera att output-mappen existerar
    # dirname: extrahera mappsökvägen från filsökvägen
    [[ ! -d "$(dirname "$output")" ]] && error_exit "Output-mappen saknas: $(dirname "$output")"
    
    # Om vi kom hit är allt OK
    log "INFO" "Filkontroll OK"
}

# ============================================================================
# HUVUDLOGIK: PROCESSKONTROLL
# ============================================================================

# Funktion: check_risks()
# Syfte: Hämta alla processer från systemet och jämför mot risklistan
# Arbetsflöde:
#   1. Läs in alla riskmönster från risklistan
#   2. Hämta alla processer med 'ps aux'
#   3. För varje process: jämför dess kommando mot alla riskmönster
#   4. Om match: flagga som riskig och loggra
check_risks() {
    log "INFO" "Skannar processer mot risklista..."
    
    # Läs riskmönster från risklistan
    # grep -v '^#': Ta bort kommentarlinjer (börjar med #)
    # grep -v '^[[:space:]]*$': Ta bort tomma rader
    # Detta resulterar i en ren lista med endast mönster
    local risk_patterns=$(grep -v '^#' "$risklist" | grep -v '^[[:space:]]*$')
    
    # Loopa igenom varje processlinje från 'ps aux --no-headers'
    # Format från ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
    while IFS= read -r line; do
        # Öka processräknaren
        ((total_processes++))
        
        # Extrahera relevant data från processlinjen med awk
        local pid=$(echo "$line" | awk '{print $2}')              # PID är fält 2
        local user=$(echo "$line" | awk '{print $1}')             # USER är fält 1
        local cpu=$(echo "$line" | awk '{print $3}')              # %CPU är fält 3
        local mem=$(echo "$line" | awk '{print $4}')              # %MEM är fält 4
        local cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++)printf "%s ",$i}')  # COMMAND börjar vid fält 11
        
        # Lagra ALLA processer (vi visar alla i JSON-outputen)
        # Format: PID|USER|CPU|MEM|COMMAND (begränsa kommando till 150 tecken)
        all_processes+=("$pid|$user|$cpu|$mem|${cmd:0:150}")
        
        # ========================================
        # Jämför processkommando mot riskmönster
        # ========================================
        while IFS= read -r pattern; do
            # grep -qi: Sök case-insensitively i kommandot
            if echo "$cmd" | grep -qi "$pattern"; then
                # MATCH! Denna process är riskig
                ((risky_processes++))
                
                # Lagra anomalien: PID|USER|COMMAND|PATTERN (begränsa kommando till 100 tecken)
                anomalies+=("$pid|$user|${cmd:0:100}|$pattern")
                
                # Loggra upptäckten
                log "WARN" "Riskig process: PID=$pid, Pattern=$pattern"
                
                # Sluta jämföra denna process mot fler mönster (break)
                break
            fi
        done <<< "$risk_patterns"
        
    done < <(ps aux --no-headers 2>/dev/null || error_exit "Kunde inte hämta processlista")
    
    # Sammanfattning
    log "INFO" "Skanning klar: $risky_processes riskiga av $total_processes totalt"
}

# ============================================================================
# JSON-EXPORT
# ============================================================================

# Funktion: export_json()
# Syfte: Generera en strukturerad JSON-fil med alla resultat
# Outputen innehåller:
#   - Metadata: scan_date, hostname, totalt/riskiga processer
#   - Severity: Risknivå baserat på antal riskiga processer
#   - all_processes: Array med alla processer
#   - anomalies: Array med endast riskiga processer
export_json() {
    log "INFO" "Skapar JSON-output..."
    
    # Skapa tidsstämpel för denna skanning
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Bestäm allvarlighetsgrad baserat på antal riskiga processer
    # Detta hjälper användaren att snabbt bedöma situationen
    local severity="LOW"
    [[ $risky_processes -gt 0 ]] && severity="MEDIUM"     # Minst 1 riskig
    [[ $risky_processes -gt 5 ]] && severity="HIGH"       # Fler än 5 riskiga
    [[ $risky_processes -gt 10 ]] && severity="CRITICAL"  # Fler än 10 riskiga
    
    # ========================================
    # Skapa JSON-struktur
    # ========================================
    # Använd en here-doc med omdirigering (> file) för att skriva JSON
    {
        # JSON Header - metadata om skanningen
        echo '{'
        echo "  \"scan_date\": \"$timestamp\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"total_processes\": $total_processes,"
        echo "  \"risky_processes_found\": $risky_processes,"
        echo "  \"severity\": \"$severity\","
        echo '  "all_processes": ['
        
        # ========================================
        # Sektion 1: Alla processer
        # ========================================
        # Loopa igenom alla processer och formatera som JSON-objekt
        local first=true
        for proc in "${all_processes[@]}"; do
            # Parsa process-datastrukturen (PID|USER|CPU|MEM|CMD)
            IFS='|' read -r pid user cpu mem cmd <<< "$proc"
            
            # Escapea specialtecken i kommandot för giltigt JSON
            # s/\"/\\\\\"}/g: Ersätt \" med \\\"
            # s/\\\\/\\\\\\\\/g: Ersätt \\\\ med \\\\\\\\\\\\\\\\\n
            cmd=$(echo "$cmd" | sed 's/"/\\"/g; s/\\/\\\\/g')\n            
            # Lägg till kommatecken före alla poster utom den första
            [[ "$first" == false ]] && echo ','
            # Skriv JSON-objekt för denna process\n            echo -n "    {\"pid\":\"$pid\",\"user\":\"$user\",\"cpu_percent\":\"$cpu\",\"memory_percent\":\"$mem\",\"command\":\"$cmd\"}"
            first=false
        done
        
        echo ''
        echo '  ],'
        echo '  "anomalies": ['
        
        # ========================================
        # Sektion 2: Riskiga processer (anomalier)
        # ========================================
        # Loopa igenom alla anomalier och formatera som JSON-objekt
        first=true
        for anomaly in "${anomalies[@]}"; do
            # Parsa anomaly-datastrukturen (PID|USER|CMD|PATTERN)
            IFS='|' read -r pid user cmd pattern <<< "$anomaly"
            
            # Escapea specialtecken
            cmd=$(echo "$cmd" | sed 's/"/\\"/g')
            pattern=$(echo "$pattern" | sed 's/"/\\"/g')
            
            # Lägg till kommatecken före alla poster utom den första
            [[ "$first" == false ]] && echo ','
            # Skriv JSON-objekt för denna anomali
            echo -n "    {\"pid\":\"$pid\",\"user\":\"$user\",\"command\":\"$cmd\",\"matched_pattern\":\"$pattern\",\"detected_time\":\"$timestamp\"}"
            first=false
        done
        
        echo ''
        echo '  ]'
        echo '}'
    } > "$output" || error_exit "Kunde inte skriva JSON-output"
    
    # Bekräfta att JSON skapats
    log "INFO" "JSON sparad: $output (Allvarlighetsgrad: $severity)"
}

# ============================================================================
# HUVUDPROGRAM
# ============================================================================

# Funktion: main()
# Syfte: Orchestrera hela säkerhetsskmanningen från start till slut
# Arbetsflöde:
#   1. Kontrollera att alla nödvändiga filer finns
#   2. Skanna processer och jämför mot risklista
#   3. Generera JSON-rapport med resultat
main() {
    log "INFO" "Linux Process Check startar..."
    
    # Steg 1: Filkontroll
    check_files
    
    # Steg 2: Huvudanalys - skanna processer mot risklista
    check_risks
    
    # Steg 3: Exportera resultaten till JSON
    export_json
    
    log "INFO" "Linux Process Check slutförd"
}

# ============================================================================
# PROGRAMSTART
# ============================================================================
# Kör main-funktionen
main
