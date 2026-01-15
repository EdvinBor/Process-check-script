# ============================================================================
# Windows Service Security Check Script
# ============================================================================
# Detta script:
# 1. Hämtar alla körande Windows-tjänster
# 2. Jämför tjänstnamnen mot en risklista
# 3. Exporterar en CSV-fil med alla tjänster
# 4. Loggar alla upptäckta risker
# ============================================================================

# ============================================================================
# KONFIGURATION
# ============================================================================
# Definiera sökvägar - alla sökvägar är relativa till scriptet själv

# $PSCommandPath: Full sökväg till detta PowerShell-script
# Split-Path: Extrahera endast mappdelen (ta bort filnamnet)
$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent

# Skapa data-mappen om den inte finns (en nivå upp från script-mappen)
$DataDir = Join-Path -Path $ScriptDir -ChildPath "..\data"
if (-not (Test-Path $DataDir)) {
    New-Item -Path $DataDir -ItemType Directory -Force | Out-Null
}

# Definiera in- och utfiler
$Output = Join-Path -Path $DataDir -ChildPath "windows_output.csv"     # Utfil: CSV med alla tjänster
$LogFile = Join-Path -Path $DataDir -ChildPath "anomalies.log"         # Loggfil: alla händelser
$RiskList = Join-Path -Path $DataDir -ChildPath "risklist.txt"         # Indata: riskabla tjänstmönster

# ============================================================================
# LOGGNING
# ============================================================================

# Funktion: Write-Log
# Syfte: Skriver loggmeddelanden till både konsolen och loggfilen
# Parametrar:
#   $Level = Loggnivå (INFO, WARN, ERROR)
#   $Message = Meddelandet som ska loggas
function Write-Log {
    param([string]$Level, [string]$Message)
    
    # Skapa en tidsstämpel i format: YYYY-MM-DD HH:MM:SS
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Formatera loggmeddelandet: [timestamp] [level] message
    $LogMsg = "[$Timestamp] [$Level] $Message"
    
    # Skriv till PowerShell-konsolen (stdout)
    Write-Host $LogMsg
    
    # Lägg till raden i loggfilen (append)
    # -ErrorAction SilentlyContinue: Ignorera fel om loggfilen inte kan skrivas
    Add-Content -Path $LogFile -Value $LogMsg -ErrorAction SilentlyContinue
}

# Funktion: Get-Services
# Syfte: Hämta alla körande Windows-tjänster från systemet
# Returvärde: Array av tjänstsobjekt med egenskaper som Name, DisplayName, Status
function Get-Services {
    Write-Log "INFO" "Hämtar aktiva tjänster..."
    
    try {
        # Get-Service: Hämtar alla tjänster från systemet
        # -ErrorAction SilentlyContinue: Ignorera tjänster som vi inte har läsrättigheter för
        # Where-Object { $_.Status -eq 'Running' }: Filtrera endast KÖRANDE tjänster
        # (andra möjliga statusar: Stopped, Paused, etc.)
        $Services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
        
        # Filtrera bort null-värden (om några skulle slippa igenom)
        $Services = $Services | Where-Object { $_ -ne $null }
        
        # Logga hur många tjänster vi hittade
        Write-Log "INFO" "Aktiva tjänster hämtade: $($Services.Count) stycken"
        
        # Returnera tjänsterna
        return $Services
    }
    catch {
        # Om något går fel, logga det och returnera tom array
        Write-Log "ERROR" "Kunde inte hämta tjänster: $_"
        return @()
    }
}

# Funktion: Check-Risks
# Syfte: Jämför alla tjänster mot risklistan och identifierar riskabla tjänster
# Parametrar:
#   $Services = Array med tjänstsobjekt att kontrollera
# Returvärde: Array med endast de tjänster som matchade riskmönster
function Check-Risks {
    param([array]$Services)
    
    Write-Log "INFO" "Startar riskkontroll..."
    
    # Läs riskmönster från risklistan
    if (-not (Test-Path $RiskList)) {
        Write-Log "WARN" "Risklistan saknas: $RiskList"
        return @()  # Returnera tom array om risklistan inte finns
    }
    
    # Läs alla rader från risklistan och filtrera:
    # -notmatch "^#": Ta bort kommentarlinjer (börjar med #)
    # -notmatch "^\s*$": Ta bort tomma rader (endast whitespace)
    $RiskPatterns = Get-Content $RiskList | Where-Object { $_ -notmatch "^#" -and $_ -notmatch "^\s*$" }
    
    # Array för att lagra de riskiga tjänsterna vi hittar
    $RiskyServices = @()
    
    # ========================================
    # Loopa igenom varje tjänst
    # ========================================
    foreach ($Service in $Services) {
        # Loopa igenom varje riskmönster
        foreach ($Pattern in $RiskPatterns) {
            # Kontrollera om tjänstens namn ELLER displayname matchar mönstret
            # -match: Regular expression matching (case-insensitive som standard i PowerShell)
            if ($Service.Name -match $Pattern -or $Service.DisplayName -match $Pattern) {
                # MATCH! Denna tjänst är riskig
                
                # Skapa ett objekt med information om den riskiga tjänsten
                $RiskyServices += [PSCustomObject]@{
                    ServiceName = $Service.Name              # Systemnamn på tjänsten
                    DisplayName = $Service.DisplayName       # Visningsnamn på tjänsten
                    Status = $Service.Status                 # Tjänstens status (Running, Stopped, etc.)
                    MatchedPattern = $Pattern                # Vilket mönster som matchade
                    DetectedTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"  # När vi discovered det
                }
                
                # Logga att vi hittade en riskig tjänst
                Write-Log "WARN" "Riskig tjänst: $($Service.Name) (Mönster: $Pattern)"
                
                # Sluta jämföra denna tjänst mot fler mönster (break från inne-loopen)
                break
            }
        }
    }
    
    # Logga sammanfattning av riskkontroll
    Write-Log "INFO" "Riskkontroll slutförd - $($RiskyServices.Count) riskiga tjänster funna"
    
    # Returnera arrayen med riskiga tjänster
    return $RiskyServices
}

# ============================================================================
# HUVUDPROGRAM
# ============================================================================
# Detta är huvudarbetsflödet för scriptet

Write-Log "INFO" "Windows Service Check startar..."

# ========================================
# STEG 1: Hämta tjänster
# ========================================
# Kalla Get-Services-funktionen för att hämta alla körande tjänster
$Services = Get-Services

# ========================================
# STEG 2: Kontrollera risker
# ========================================
# Kalla Check-Risks-funktionen för att jämföra mot risklistan
$RiskyServices = Check-Risks $Services

# ========================================
# STEG 3: Exportera till CSV
# ========================================
# Exportera ALLA tjänster till en CSV-fil för arkivering/analys
# Select-Object: Välj endast de kolumner vi vill exportera
# Export-Csv: Exportera till CSV-format
# -NoTypeInformation: Skippa PowerShell typinformation
# -Encoding UTF8: Använd UTF-8 encoding för internationella tecken
$Services | Select-Object Name, DisplayName, Status | Export-Csv -Path $Output -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue

Write-Log "INFO" "CSV exporterad: $Output"

# ========================================
# STEG 4: Bestäm allvarlighetsgrad
# ========================================
# Klassificera risknivå baserat på antalet riskiga tjänster
# Detta hjälper användaren att snabbt bedöma situationen
$Severity = switch ($RiskyServices.Count) {
    0 { "LOW" }                    # 0 riskiga tjänster
    { $_ -le 3 } { "MEDIUM" }     # 1-3 riskiga tjänster
    { $_ -le 5 } { "HIGH" }       # 4-5 riskiga tjänster
    default { "CRITICAL" }        # Fler än 5 riskiga tjänster
}

# ========================================
# STEG 5: Rapportering
# ========================================
# Skriv ut en sammanfattning av resultaten
Write-Log "INFO" "========== RESULTAT =========="
Write-Log "INFO" "Totala tjänster: $($Services.Count)"
Write-Log "INFO" "Riskiga tjänster: $($RiskyServices.Count)"
Write-Log "INFO" "Allvarlighetsgrad: $Severity"

# Om vi hittade riskiga tjänster, lista dem
if ($RiskyServices.Count -gt 0) {
    Write-Log "INFO" "Riskiga tjänster:"
    $RiskyServices | ForEach-Object { Write-Log "WARN" "  - $($_.ServiceName)" }
}

Write-Log "INFO" "========== Windows Service Check slutförd ==========" 
