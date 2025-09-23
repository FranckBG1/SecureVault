@echo off
REM Se placer dans le dossier du .bat (donc ton projet)
cd /d "%~dp0"

REM activer l'environnement virtuel si présent
if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)

REM lancer desktop.py avec python du venv si possible
if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" desktop.py
) else (
    python desktop.py
)
