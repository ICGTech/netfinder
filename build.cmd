@echo off
rem Builds dist\NetFinder.exe (single file, no .NET install needed on the target PC).
rem Requires the .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0
dotnet publish src\NetFinder\NetFinder.csproj -c Release -o dist
if errorlevel 1 exit /b 1
echo.
echo Done: dist\NetFinder.exe
