@echo off
setlocal
cd /d "%~dp0"
call npm install
if errorlevel 1 goto failed
call npm run check
if errorlevel 1 goto failed
call npx wrangler login
if errorlevel 1 goto failed
call npm run deploy:upgrade
if errorlevel 1 goto failed
pause
exit /b 0
:failed
echo Deployment stopped. Read the error above; no automatic reset or database deletion was performed.
pause
exit /b 1
