# AegisFlow desktop launcher

`AegisFlow.exe` (in the project root) is a one-click launcher for the whole
platform. Double-click it and it will:

1. Start the **backend** API (FastAPI, mock mode — no external services or keys)
   on http://localhost:8000.
2. Start the **frontend** SOC console (Vite) and detect its URL.
3. Open your default browser to the UI once it is serving.
4. On **first run only**, automatically set up anything missing — the Python
   virtual environment + backend dependencies, and `npm install` for the
   frontend. Subsequent launches are fast.

Closing the console window (or pressing **Ctrl+C**) stops both services.

At the login screen use the **dev-mode** button (tenant `acme`, role
`tier3_analyst`).

## Requirements

- **Python 3.11+** and **Node.js 18+** on your `PATH` (only needed the first time,
  for setup; the launcher checks and tells you if either is missing).
- Windows.

## Rebuilding the .exe

The executable is produced from `installer/AegisFlow.cs` with the C# compiler that
ships in the Windows .NET Framework — no downloads required:

```powershell
.\installer\build.ps1
```
