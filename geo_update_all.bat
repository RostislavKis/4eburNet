@echo off
chcp 65001 > nul
setlocal
cd /d "%~dp0"

echo.
echo ╔══════════════════════════════════════╗
echo ║   4eburNet GeoIP Full Update         ║
echo ║   D:\Проекты\filter                  ║
echo ╚══════════════════════════════════════╝
echo.

:: Создать ярлык на рабочем столе (однократно)
if not exist "%USERPROFILE%\Desktop\4eburNet GeoIP Update.lnk" (
    powershell -ExecutionPolicy Bypass -File tools\create_shortcut.ps1
)

:: Проверить Python
python --version > nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ОШИБКА] Python не найден. Установить python.org
    pause & exit /b 1
)

:: Проверить репо filter
if not exist "..\filter\geo\" (
    echo [ОШИБКА] Репо filter не найден: D:\Проекты\filter
    echo Клонировать: git clone https://github.com/RostislavKis/filter ..\filter
    pause & exit /b 1
)

:: ШАГ 1: Обновить .lst файлы
echo [1/4] Скачиваю и обновляю .lst файлы...
python tools\update_geo.py --filter-repo ..\filter
if %ERRORLEVEL% neq 0 (
    echo [ОШИБКА] update_geo.py завершился с ошибкой
    pause & exit /b 1
)
echo.

:: ШАГ 2: Если есть GeoLite2-Country.mmdb — конвертировать
if exist "..\filter\tools\GeoLite2-Country.mmdb" (
    echo [2/4] Конвертирую MaxMind .mmdb --^> geoip-ru.lst...
    python ..\filter\tools\mmdb_to_lst.py ^
        --db ..\filter\tools\GeoLite2-Country.mmdb ^
        --country RU ^
        --output ..\filter\geo\geoip-ru.lst
    echo.
) else (
    echo [2/4] GeoLite2-Country.mmdb не найден -- пропускаю mmdb конвертацию
    echo       Скачать бесплатно: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    echo       Положить в: D:\Проекты\filter\tools\GeoLite2-Country.mmdb
    echo.
)

:: ШАГ 3: Компилировать .lst → .gbin через WSL geo_compile
echo [3/4] Компилирую .lst --^> .gbin...
wsl bash -c "cd ~/4eburnet-dev/project/4eburNet && make -f Makefile.dev geo_compile 2>/dev/null; for lst in /mnt/d/Проекты/filter/geo/*.lst; do name=$(basename $lst .lst); echo \"  Компилирую $name...\"; ./tools/geo_compile \"$lst\" \"/mnt/d/Проекты/filter/geo/$name.gbin\" 2>&1 || true; done"
echo.

:: ШАГ 4: Коммит и пуш в filter репо
echo [4/4] Пуш в GitHub...
cd ..\filter
git add geo\ rule-sets\
git diff --cached --quiet
if %ERRORLEVEL% equ 0 (
    echo Нет изменений для коммита.
) else (
    for /f "tokens=*" %%i in ('powershell -Command "Get-Date -Format 'yyyy-MM-dd'"') do set TODAY=%%i
    git commit -m "geo: update %TODAY%"
    git push origin master 2>nul || git push origin main
    echo [OK] Запушено в GitHub
)
cd /d "%~dp0"

echo.
echo ╔══════════════════════════════════════╗
echo ║   Готово! Нажмите любую клавишу      ║
echo ╚══════════════════════════════════════╝
pause > nul
