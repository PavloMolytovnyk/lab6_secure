@echo off
cd /d "%~dp0"
node --version
echo Open http://127.0.0.1:3000 in your browser after startup.
node src/server.mjs
pause
