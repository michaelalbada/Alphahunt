ROLE_PROCESSES = {
    # Privileged & IT Ops
    "admin": [
        # native admin tools
        "powershell.exe", "cmd.exe", "wmiPrvSE.exe", "mmc.exe", "regedit.exe",
        "schtasks.exe", "psexec.exe", "taskmgr.exe", "gpupdate.exe",
        # security consoles / agents
        "defender.exe", "crowdstrike.exe", "kibana.exe",
        # RMM & maintenance
        "teamviewer.exe", "anydesk.exe", "vncserver.exe", "patchmgr.exe",
        # hyper-visors / vm tooling
        "vmware-vmx.exe", "vboxheadless.exe"
    ],

    # Software & data engineers
    "engineer": [
        # IDEs / editors
        "vscode.exe", "pycharm.exe", "intellij64.exe", "eclipse.exe",
        "sublime_text.exe",
        # compilers / runtimes
        "python.exe", "java.exe", "node.exe", "go.exe", "dotnet.exe",
        # build / CI
        "mvn.cmd", "gradle.exe", "npm.exe", "yarn.exe", "make.exe",
        # VCS & tooling
        "git.exe", "ssh.exe", "pg_dump.exe", "kubectl.exe", "docker.exe",
        # misc dev
        "postman.exe", "insomnia.exe"
    ],

    # Quota-carrying field & inside sales
    "sales": [
        "chrome.exe", "msedge.exe", "firefox.exe",
        "outlook.exe", "teams.exe", "slack.exe", "zoom.exe",
        "powerpoint.exe", "excel.exe",
        "salesforce.exe", "hubspot.exe", "docusign.exe"
    ],

    # Finance, HR, Legal, Ops, etc.
    "corporate": [
        "excel.exe", "word.exe", "powerpoint.exe", "onenote.exe",
        "outlook.exe", "teams.exe", "acrobat.exe",
        "sapgui.exe", "oracle_fin.exe", "workday.exe",
        "quickbooks.exe", "visio.exe"
    ],

    # Summer interns & temps
    "intern": [
        "edge.exe", "chrome.exe", "firefox.exe",
        "notepad.exe", "wordpad.exe",
        "vscode.exe",
        "teams.exe", "zoom.exe"
    ]
}

# Base directories each role normally uses — %USER% will be replaced by account name
ROLE_DIRS = {
    "admin": [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Scripts",
        r"C:\Temp"
    ],
    "engineer": [
        r"C:\src\projects",
        r"C:\Users\%USER%\.ssh",
        r"C:\Users\%USER%\AppData\Local\Temp",
        r"/home/%USER%/workspace",
        r"/opt/docker/volumes"
    ],
    "sales": [
        r"C:\Users\%USER%\Documents\Proposals",
        r"C:\Users\%USER%\Downloads",
        r"C:\Users\%USER%\Desktop",
        r"C:\Users\%USER%\OneDrive\Presentations"
    ],
    "corporate": [
        r"C:\Users\%USER%\Documents\Finance",
        r"C:\Users\%USER%\Documents\HR",
        r"\\fileserver01\Shared\Legal",
        r"C:\Users\%USER%\Downloads"
    ],
    "intern": [
        r"C:\Users\%USER%\Downloads",
        r"C:\Users\%USER%\Documents",
        r"C:\Temp"
    ]
}

# Typical file extensions per role (for generated filenames)
ROLE_EXTS = {
    "admin":     [".ps1", ".bat", ".vbs", ".log", ".csv"],
    "engineer":  [".py", ".js", ".go", ".java", ".ts", ".json", ".yaml", ".txt"],
    "sales":     [".pptx", ".xlsx", ".pdf", ".docx"],
    "corporate": [".xlsx", ".docx", ".csv", ".pdf"],
    "intern":    [".txt", ".md", ".pdf", ".pptx"]
}
