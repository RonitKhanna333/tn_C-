@echo off
echo Installing Python dependencies...
pip install pycryptodome psutil tqdm boto3

echo Installing .NET 6.0 SDK if not already installed...
winget install Microsoft.DotNet.SDK.6

echo All dependencies installed.
pause
