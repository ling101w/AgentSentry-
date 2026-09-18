@echo off
title Keep OpenClaw running
echo.
echo === Keep OpenClaw / Xuanjian running ===
echo Do NOT close this window.
echo WSL idle-stop is why the page vanishes after a while.
echo.

wsl -e bash -lc "mkdir -p /root/.openclaw && install -m 755 /mnt/e/cslearn/AgentSentry/xuanjian/AgentSentry/openclaw-plugin/scripts/keep-openclaw.sh /root/.openclaw/keep-openclaw.sh"
if errorlevel 1 goto FAIL

echo Starting OpenClaw...
wsl -e bash /root/.openclaw/keep-openclaw.sh start
if errorlevel 1 goto NOTREADY

echo 8765 is listening. Opening pages...
start "" "http://127.0.0.1:8765/overview"
ping -n 2 127.0.0.1 >nul
start "" "http://127.0.0.1:8765/command-lab"
echo.
echo Opened:
echo   Main page  http://127.0.0.1:8765/overview
echo   Demo page  http://127.0.0.1:8765/command-lab
echo If the old page is still showing, press Ctrl+F5.
echo.
echo Watching 8765. Leave this window open.
echo.

wsl -e bash /root/.openclaw/keep-openclaw.sh watch
echo.
echo Watcher stopped. The page may go away if WSL sleeps.
pause
exit /b 0

:FAIL
echo.
echo Could not install keep-alive helper in WSL.
echo Check WSL, then run: wsl -e bash -lc "openclaw gateway status"
pause
exit /b 1

:NOTREADY
echo.
echo Gateway started, but 8765 is not up yet.
echo Run: wsl -e bash -lc "openclaw gateway status"
pause
exit /b 1
