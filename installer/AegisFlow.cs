// AegisFlow desktop launcher.
//
// A self-contained Windows launcher: double-click AegisFlow.exe and it boots the
// backend (FastAPI, mock mode) and the frontend (Vite), waits until the UI is
// serving, and opens the default browser to it. On first run it performs any
// missing setup automatically (Python venv + deps, npm install). Closing the
// console window (or Ctrl+C) stops both services.
//
// Built with the C# compiler that ships in the Windows .NET Framework, so no
// external tooling or downloads are required to produce the .exe.
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;

class AegisFlow
{
    static readonly System.Collections.Generic.List<Process> Children =
        new System.Collections.Generic.List<Process>();
    static readonly ManualResetEvent UiReady = new ManualResetEvent(false);
    static string _uiUrl = "http://localhost:5173";

    static int Main()
    {
        Console.Title = "AegisFlow — AI Security Investigation Platform";
        Banner();

        // The .exe lives at the repository root; resolve backend/ and frontend/.
        string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        string backend = Path.Combine(root, "backend");
        string frontend = Path.Combine(root, "frontend");

        if (!Directory.Exists(backend) || !Directory.Exists(frontend))
        {
            Fail("Place AegisFlow.exe in the project root (next to the 'backend' "
                 + "and 'frontend' folders). Not found at:\n  " + root);
            return 1;
        }

        AppDomain.CurrentDomain.ProcessExit += (s, e) => StopAll();
        Console.CancelKeyPress += (s, e) => { e.Cancel = true; StopAll(); Environment.Exit(0); };

        try
        {
            string python = EnsureBackend(backend);
            EnsureFrontendDeps(frontend);

            Info("Starting backend  ->  http://localhost:8000  (API docs: /docs)");
            StartBackend(python, backend);

            Info("Starting frontend ...");
            StartFrontend(frontend);

            Info("Waiting for the UI to come up ...");
            if (!UiReady.WaitOne(TimeSpan.FromSeconds(90)))
                Warn("UI did not report ready in time; opening " + _uiUrl + " anyway.");

            Thread.Sleep(1000);
            Info("Opening " + _uiUrl);
            OpenBrowser(_uiUrl);

            Console.WriteLine();
            Info("AegisFlow is running. Log in with the dev button "
                 + "(tenant 'acme', role 'tier3_analyst').");
            Info("Press Ctrl+C or close this window to stop.");
            Console.WriteLine(new string('-', 70));

            // Block until a child exits or the user stops us.
            while (true)
            {
                foreach (Process p in Children.ToArray())
                    if (p.HasExited)
                    {
                        Warn("A service exited (code " + p.ExitCode + "). Shutting down.");
                        StopAll();
                        return 1;
                    }
                Thread.Sleep(700);
            }
        }
        catch (Exception ex)
        {
            Fail(ex.Message);
            StopAll();
            return 1;
        }
    }

    // ---- setup ------------------------------------------------------------

    static string EnsureBackend(string backend)
    {
        string venvPy = Path.Combine(backend, ".venv\\Scripts\\python.exe");
        if (File.Exists(venvPy))
            return venvPy;

        Warn("First run: creating the Python environment (this can take a few minutes)...");
        if (!OnPath("python"))
            throw new Exception("Python 3.11+ is required but was not found on PATH. "
                                + "Install it from https://www.python.org/downloads/ and re-run.");

        Run("python", "-m venv .venv", backend, true);
        Run(venvPy, "-m pip install --upgrade pip", backend, true);
        Run(venvPy, "-m pip install -e \".[dev]\"", backend, true);
        if (!File.Exists(venvPy))
            throw new Exception("Failed to create the backend environment.");
        return venvPy;
    }

    static void EnsureFrontendDeps(string frontend)
    {
        if (Directory.Exists(Path.Combine(frontend, "node_modules")))
            return;
        Warn("First run: installing frontend dependencies (npm install)...");
        if (!OnPath("node"))
            throw new Exception("Node.js 18+ is required but was not found on PATH. "
                                + "Install it from https://nodejs.org/ and re-run.");
        Run("cmd.exe", "/c npm install", frontend, true);
    }

    // ---- services ---------------------------------------------------------

    static void StartBackend(string python, string backend)
    {
        var psi = new ProcessStartInfo(python,
            "-m uvicorn app.main:app --port 8000")
        {
            WorkingDirectory = backend,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.EnvironmentVariables["AEGIS_ENV"] = "local";
        psi.EnvironmentVariables["AEGIS_CONNECTOR_MODE"] = "mock";
        psi.EnvironmentVariables["AEGIS_AUTH_DEV_BYPASS"] = "true";
        Spawn(psi, "backend", false);
    }

    static void StartFrontend(string frontend)
    {
        var psi = new ProcessStartInfo("cmd.exe", "/c npm run dev")
        {
            WorkingDirectory = frontend,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        Spawn(psi, "frontend", true);
    }

    static readonly Regex UrlRe = new Regex(@"https?://localhost:\d+",
        RegexOptions.IgnoreCase);

    static void Spawn(ProcessStartInfo psi, string tag, bool watchForUrl)
    {
        var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
        DataReceivedEventHandler onData = (s, e) =>
        {
            if (e.Data == null) return;
            Console.WriteLine("[" + tag + "] " + e.Data);
            if (watchForUrl && !UiReady.WaitOne(0))
            {
                Match m = UrlRe.Match(e.Data);
                if (m.Success) { _uiUrl = m.Value; UiReady.Set(); }
            }
        };
        p.OutputDataReceived += onData;
        p.ErrorDataReceived += onData;
        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        Children.Add(p);
    }

    // ---- helpers ----------------------------------------------------------

    static void Run(string file, string args, string cwd, bool wait)
    {
        var psi = new ProcessStartInfo(file, args)
        {
            WorkingDirectory = cwd,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        var p = Process.Start(psi);
        p.OutputDataReceived += (s, e) => { if (e.Data != null) Console.WriteLine("  " + e.Data); };
        p.ErrorDataReceived += (s, e) => { if (e.Data != null) Console.WriteLine("  " + e.Data); };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        if (wait) p.WaitForExit();
    }

    static bool OnPath(string exe)
    {
        try
        {
            var psi = new ProcessStartInfo("where", exe)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
            var p = Process.Start(psi);
            p.WaitForExit();
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    static void OpenBrowser(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { Warn("Could not open the browser automatically; visit " + url); }
    }

    static void StopAll()
    {
        foreach (Process p in Children.ToArray())
        {
            try { if (!p.HasExited) KillTree(p.Id); } catch { }
        }
        Children.Clear();
    }

    static void KillTree(int pid)
    {
        try
        {
            var psi = new ProcessStartInfo("taskkill", "/PID " + pid + " /T /F")
            { UseShellExecute = false, CreateNoWindow = true };
            Process.Start(psi).WaitForExit();
        }
        catch { }
    }

    static void Banner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("   AegisFlow — AI-Powered Security Investigation Platform");
        Console.WriteLine("   " + new string('=', 54));
        Console.ResetColor();
        Console.WriteLine();
    }

    static void Info(string m)  { Line(ConsoleColor.Green, "[+] " + m); }
    static void Warn(string m)  { Line(ConsoleColor.Yellow, "[!] " + m); }
    static void Fail(string m)
    {
        Line(ConsoleColor.Red, "[x] " + m);
        Console.WriteLine();
        Console.WriteLine("Press any key to exit...");
        try { Console.ReadKey(); } catch { }
    }
    static void Line(ConsoleColor c, string m)
    {
        Console.ForegroundColor = c; Console.WriteLine(m); Console.ResetColor();
    }
}
