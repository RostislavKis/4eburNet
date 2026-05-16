@echo off
setlocal EnableDelayedExpansion
echo [4eburNet] GEO UPDATE STARTED -- %date% %time%
echo.

set FILTER_DIR=D:\Проекты\filter
set EBURNET_DIR=D:\Проекты\4eburNet

REM === 1. Скачать свежие .lst (--dry-run: единый коммит делается в шаге 5) ===
echo [1/5] Downloading geo source data...
wsl bash -c "cd '/mnt/d/Проекты/4eburNet' && python3 tools/update_geo.py --filter-repo '/mnt/d/Проекты/filter' --dry-run 2>&1"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: update_geo.py завершился с ошибкой
    pause
    exit /b 1
)

REM === 2. Собрать geo_compile для хоста ===
echo.
echo [2/5] Building geo_compile...
wsl bash -c "gcc '/mnt/d/Проекты/4eburNet/tools/geo_compile.c' -I'/mnt/d/Проекты/4eburNet/core/include' -o /tmp/geo_compile 2>&1 && echo OK"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: geo_compile не собрался
    pause
    exit /b 1
)

REM === 3. Компилировать .lst -> .gbin с правильными region/cat_type ===
echo.
echo [3/5] Compiling .lst to .gbin...
wsl bash -c "/tmp/geo_compile '/mnt/d/Проекты/filter/geo/geoip-ru.lst'         '/mnt/d/Проекты/filter/geo/geoip-ru.gbin'         1 0 && echo geoip-ru.gbin OK"
wsl bash -c "/tmp/geo_compile '/mnt/d/Проекты/filter/geo/geosite-ru.lst'        '/mnt/d/Проекты/filter/geo/geosite-ru.gbin'        1 0 && echo geosite-ru.gbin OK"
wsl bash -c "/tmp/geo_compile '/mnt/d/Проекты/filter/geo/geosite-ads.lst'       '/mnt/d/Проекты/filter/geo/geosite-ads.gbin'       0 1 && echo geosite-ads.gbin OK"
wsl bash -c "/tmp/geo_compile '/mnt/d/Проекты/filter/geo/geosite-trackers.lst'  '/mnt/d/Проекты/filter/geo/geosite-trackers.gbin'  0 2 && echo geosite-trackers.gbin OK"
wsl bash -c "/tmp/geo_compile '/mnt/d/Проекты/filter/geo/geosite-threats.lst'   '/mnt/d/Проекты/filter/geo/geosite-threats.gbin'   0 3 && echo geosite-threats.gbin OK"
wsl bash -c "/tmp/geo_compile '/mnt/d/Проекты/filter/geo/opencck-domains.lst'   '/mnt/d/Проекты/filter/geo/opencck-domains.gbin'   1 0 && echo opencck-domains.gbin OK"

REM === 4. Обновить checksums + timestamp в манифестах ===
echo.
echo [4/5] Updating checksums and manifests...
wsl bash -c "cd '/mnt/d/Проекты/filter/geo' && sha256sum *.gbin *.lst > ../checksums.sha256 && echo CHECKSUMS_UPDATED"
wsl bash -c "python3 '/mnt/d/Проекты/4eburNet/tools/geo_manifest_update.py' '/mnt/d/Проекты/filter' 2>&1"

REM === 5. Коммит и пуш в filter репо ===
echo.
echo [5/5] Pushing to github.com/RostislavKis/filter...
cd /d %FILTER_DIR%
git add geo\
git diff --cached --stat
git commit -m "geo: auto-update %date%"
git push origin master
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [4eburNet] GEO UPDATE COMPLETE
    echo Пользователи получат обновление через Dashboard ^> Geo Update
) else (
    echo ERROR: git push не прошёл -- проверьте git credentials
)
pause
