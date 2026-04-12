@echo off
chcp 65001 > nul
cd /d "%~dp0"
echo === Синхронизация 4eburNet D:\Проекты → WSL ===
echo.

wsl -d Ubuntu-24.04 -- bash -c "rsync -av --delete --exclude='build/' --exclude='.git/' --exclude='prebuilt/mipsel/4eburnetd' --exclude='prebuilt/aarch64/4eburnetd' --exclude='.vs/' --exclude='__pycache__/' /mnt/d/Проекты/4eburNet/ ~/4eburnet-dev/project/4eburNet/ && echo SYNC_OK"

if %ERRORLEVEL% neq 0 (
    echo [ОШИБКА] rsync завершился с ошибкой
    pause
    exit /b 1
)
echo [OK] Синхронизация завершена
echo.

set /p REBUILD="Пересобрать бинарник mipsel? (y/n): "
if /i "%REBUILD%"=="y" (
    echo === Cross-compile mipsel ===
    wsl -d Ubuntu-24.04 -- bash -c "cd ~/4eburnet-dev/project/4eburNet/core && export STAGING_DIR=~/4eburnet-dev/sdk/mipsel-mt7621/sdk-mipsel-mt7621/staging_dir/toolchain-mipsel_24kc_gcc-12.3.0_musl && make -f Makefile.dev cross-mipsel TC_MIPSEL=$STAGING_DIR/bin WOLFSSL_MIPSEL=/usr/local/musl-wolfssl-mipsel 2>&1 | tail -3 && $STAGING_DIR/bin/mipsel-openwrt-linux-musl-strip ../prebuilt/mipsel/4eburnetd && ls -lh ../prebuilt/mipsel/4eburnetd"
    if %ERRORLEVEL% neq 0 (
        echo [ОШИБКА] сборка провалилась
        pause
        exit /b 1
    )
    echo [OK] Бинарник собран
    echo.
)

set /p DEPLOY="Задеплоить на EC330 (192.168.2.1)? (y/n): "
if /i "%DEPLOY%"=="y" (
    echo === Deploy на EC330 ===
    wsl -d Ubuntu-24.04 -- bash -c "cp ~/4eburnet-dev/project/4eburNet/prebuilt/mipsel/4eburnetd /tmp/4eburnetd-deploy"
    scp -O -o StrictHostKeyChecking=no "\\wsl$\Ubuntu-24.04\tmp\4eburnetd-deploy" root@192.168.2.1:/tmp/4eburnetd-new
    ssh -o StrictHostKeyChecking=no root@192.168.2.1 "kill $(cat /var/run/4eburnet.pid 2>/dev/null) 2>/dev/null; sleep 1; rm -f /usr/sbin/4eburnetd; mv /tmp/4eburnetd-new /usr/sbin/4eburnetd; chmod +x /usr/sbin/4eburnetd; /usr/sbin/4eburnetd -v; /usr/sbin/4eburnetd -c /etc/config/4eburnet -d"
    echo [OK] Бинарник на роутере обновлён и демон запущен
    echo.
)

echo.
echo [ГОТОВО]
pause > nul
