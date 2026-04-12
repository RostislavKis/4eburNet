@echo off
chcp 65001 > nul
cd /d "%~dp0"
echo === 4eburNet GeoIP Updater ===
echo.
python tools\update_geo.py --filter-repo ..\filter %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ОШИБКА] Скрипт завершился с ошибкой
    pause
    exit /b 1
)
echo.
echo [ГОТОВО] Нажмите любую клавишу для выхода
pause > nul
