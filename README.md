# Process-check-script

Samling av tre små verktyg som skannar processer/tjänster på Windows och Linux och genererar en sammanställd säkerhetsrapport.

## Översikt
- [powershell/windows_check.ps1](powershell/windows_check.ps1): Hämtar körande Windows-tjänster, matchar mot risklistan och sparar CSV + logg.
- [bash/linux_check.sh](bash/linux_check.sh): Skannar aktiva Linux-processer, matchar mot risklistan och sparar JSON + logg.
- [python/analysis_engine.py](python/analysis_engine.py): Läser båda resultaten, klassificerar risker och skriver en TXT-rapport.

## Förutsättningar
- En risklista i data/risklist.txt (regex eller textsträngar, en per rad, # för kommentarer).
- PowerShell 5+ på Windows, Bash på Linux/macOS, Python 3.10+ för analyssteget.
- Skrivbehörighet till data/ och report/ (skapas automatiskt om de saknas av Python-skriptet).

## Köra skanningarna
1) Windows-tjänster (PowerShell)
```powershell
cd powershell
./windows_check.ps1
# Output: data/windows_output.csv och logg i data/anomalies.log
```

2) Linux-processer (Bash)
```bash
cd bash
bash linux_check.sh
# Output: data/linux_output.json och logg i data/anomalies.log
```

3) Generera slutrapport (Python)
```bash
cd python
python analysis_engine.py
# Output: report/security_report_YYYYMMDD_HHMMSS.txt
```

4) (Extra)Generera slutrapport (Python)
```bash
cd python
python analysis_engine_advanced.py
# Output: report/security_report_YYYYMMDD_HHMMSS.html
```

## Input/Output-filer
- Input: data/risklist.txt används av båda skannrarna.
- Output: data/windows_output.csv, data/linux_output.json, data/anomalies.log (gemensam logg).
- Rapport: report/security_report_*.txt (kan öppnas i valfri texteditor).

-Extra:  report/security_report_YYYYMMDD_HHMMSS.html

```