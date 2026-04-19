@echo off
chcp 65001 > nul
setlocal
cd /d "%~dp0"

set FILTER_REPO=%~dp0..\filter

echo.
echo ╔══════════════════════════════════════╗
echo ║   4eburNet GeoIP Full Update         ║
echo ║   %FILTER_REPO%
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
if not exist "%FILTER_REPO%\geo\" (
    echo [ОШИБКА] Репо filter не найден: %FILTER_REPO%
    echo Клонировать: git clone https://github.com/RostislavKis/filter "%FILTER_REPO%"
    pause & exit /b 1
)

:: ШАГ 1: Обновить .lst файлы
echo [1/4] Скачиваю и обновляю .lst файлы...
python tools\update_geo.py --filter-repo "%FILTER_REPO%"
if %ERRORLEVEL% neq 0 (
    echo [ОШИБКА] update_geo.py завершился с ошибкой
    pause & exit /b 1
)
echo.

:: ШАГ 2: Если есть GeoLite2-Country.mmdb — конвертировать
if exist "%FILTER_REPO%\tools\GeoLite2-Country.mmdb" (
    echo [2/4] Конвертирую MaxMind .mmdb --^> geoip-ru.lst...
    python "%FILTER_REPO%\tools\mmdb_to_lst.py" ^
        --db "%FILTER_REPO%\tools\GeoLite2-Country.mmdb" ^
        --country RU ^
        --output "%FILTER_REPO%\geo\geoip-ru.lst"
    echo.
) else (
    echo [2/4] GeoLite2-Country.mmdb не найден -- пропускаю mmdb конвертацию
    echo       Скачать бесплатно: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    echo       Положить в: %FILTER_REPO%\tools\GeoLite2-Country.mmdb
    echo.
)

:: ШАГ 3: Компилировать .lst → .gbin через WSL geo_compile
echo [3/4] Компилирую .lst --^> .gbin...
wsl bash -c "
  cd ~/4eburnet-dev/project/4eburNet/core
  make -f Makefile.dev geo_compile
  if [ ! -f ../tools/geo_compile ]; then
    echo '[ОШИБКА] geo_compile не собран — пропускаю компиляцию .gbin'
    exit 1
  fi
  for lst in /mnt/d/Проекты/filter/geo/*.lst; do
    name=\$(basename \$lst .lst)
    echo Компилирую \$name...
    ../tools/geo_compile \$lst /mnt/d/Проекты/filter/geo/\$name.gbin \
      && echo OK: \$name.gbin || echo WARN: \$name не скомпилирован
  done
"
if %ERRORLEVEL% neq 0 (
    echo [WARN] Компиляция .gbin не выполнена — используются старые файлы
)
echo.

:: ШАГ 4: Коммит и пуш в filter репо
echo [4/4] Пуш в GitHub...
cd /d "%FILTER_REPO%"
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
