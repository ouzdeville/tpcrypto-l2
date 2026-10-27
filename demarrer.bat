@echo off
REM Lanceur Windows pour le TP crypto (L2).
REM Double-cliquez sur ce fichier, ou lancez-le depuis PowerShell.

cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 lancer.py
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        python lancer.py
    ) else (
        echo.
        echo Python n'est pas installe ou n'est pas dans le PATH.
        echo Installez Python 3.10+ depuis https://www.python.org/downloads/
        echo en cochant "Add Python to PATH".
    )
)

echo.
pause
