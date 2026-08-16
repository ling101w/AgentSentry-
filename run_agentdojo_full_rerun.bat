@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Run this file from any directory. %~dp0 is the project root.
set "ROOT=%~dp0"
set "PY=C:\Users\ling1\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
set "NODE=C:\Users\ling1\.workbuddy\binaries\node\versions\22.22.2\node.exe"

if not exist "%ROOT%.env" (
  echo ERROR: .env was not found: "%ROOT%.env"
  exit /b 2
)
if not exist "%PY%" (
  echo ERROR: Python was not found: "%PY%"
  exit /b 2
)
if not exist "%NODE%" (
  echo ERROR: Node was not found: "%NODE%"
  exit /b 2
)

rem Load simple KEY=VALUE entries from the project .env.
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ROOT%.env") do (
  if not "%%A"=="" set "%%A=%%B"
)

rem The project .env uses baseurl, key, and model.
set "baseurl=%baseurl:"=%"
set "key=%key:"=%"
set "model=%model:"=%"

if not defined baseurl (
  echo ERROR: .env is missing baseurl
  exit /b 2
)
if not defined key (
  echo ERROR: .env is missing key
  exit /b 2
)
if not defined model (
  echo ERROR: .env is missing model
  exit /b 2
)

set "OPENAI_COMPATIBLE_BASE_URL=%baseurl%"
set "OPENAI_COMPATIBLE_API_KEY=%key%"
set "AGENTSENTRY_API_KEY=%key%"

pushd "%ROOT%" || exit /b 2

echo WARNING: running with --allow-dirty because the workspace has uncommitted changes.
echo WARNING: all generated results will be marked reportable=false.
echo.

call :run_one agentsentry workspace
if errorlevel 1 goto failed
call :run_one agentsentry banking
if errorlevel 1 goto failed
call :run_one agentsentry travel
if errorlevel 1 goto failed
call :run_one agentsentry slack
if errorlevel 1 goto failed
call :run_one no-defense workspace
if errorlevel 1 goto failed
call :run_one no-defense banking
if errorlevel 1 goto failed
call :run_one no-defense travel
if errorlevel 1 goto failed
call :run_one no-defense slack
if errorlevel 1 goto failed

echo.
echo ALL 8 FULL RUNS FINISHED.
echo Results: runtime\agentdojo-full-rerun\
popd
exit /b 0

:run_one
set "DEFENSE=%~1"
set "SUITE=%~2"
echo.
echo ============================================================
echo START: %SUITE% / %DEFENSE%
echo ============================================================

if /i "%DEFENSE%"=="agentsentry" (
  "%PY%" scripts\run_agentdojo_native.py ^
    --selection "evaluation\native\native_%SUITE%_full_v1_selection.json" ^
    --defense agentsentry ^
    --policy-profile competition ^
    --allow-dirty ^
    --model openai-compatible ^
    --model-id "%model%" ^
    --openai-compatible-system-role system ^
    --node "%NODE%" ^
    --provider-timeout-seconds 90 ^
    --provider-max-retries 2 ^
    --judge-base-url "%baseurl%" ^
    --judge-model "%model%" ^
    --judge-timeout-ms 20000 ^
    --output-root "runtime\agentdojo-full-rerun\agentsentry\%SUITE%"
) else (
  "%PY%" scripts\run_agentdojo_native.py ^
    --selection "evaluation\native\native_%SUITE%_full_v1_selection.json" ^
    --defense no-defense ^
    --allow-dirty ^
    --model openai-compatible ^
    --model-id "%model%" ^
    --openai-compatible-system-role system ^
    --node "%NODE%" ^
    --provider-timeout-seconds 90 ^
    --provider-max-retries 2 ^
    --output-root "runtime\agentdojo-full-rerun\no-defense\%SUITE%"
)

if errorlevel 1 (
  echo FAILED: %SUITE% / %DEFENSE%
  exit /b 1
)
echo FINISHED: %SUITE% / %DEFENSE%
exit /b 0

:failed
echo.
echo Benchmark stopped because one run failed.
popd
exit /b 1
