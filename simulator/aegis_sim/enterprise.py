"""A deterministic synthetic organisation: people, devices, servers, network, SaaS destinations."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

FIRST_NAMES = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "niaj",
    "olivia", "peggy", "rupert", "sybil", "trent", "victor", "wendy", "xavier", "yara", "zane", "aarav",
    "ananya", "arjun", "diya", "ishaan", "kavya", "meera", "nikhil", "priya", "rahul", "riya", "rohan",
    "sanya", "tanvi", "vihaan", "zara", "leo", "mia", "noah", "emma", "liam", "ava", "ethan", "sofia",
    "lucas", "amelia", "mason", "harper", "logan", "ella", "james", "chloe", "ben", "nora", "sam", "ruby",
]
DEPARTMENTS = ["engineering", "finance", "hr", "sales", "legal", "operations", "marketing", "it"]
COUNTRY_HOME = "IN"
TRAVEL_COUNTRIES = ["US", "GB", "SG", "DE"]

SAAS = [  # (domain, ip, port) — benign destinations
    ("outlook.office365.com", "52.96.165.18", 443),
    ("teams.microsoft.com", "52.113.194.132", 443),
    ("login.microsoftonline.com", "20.190.151.68", 443),
    ("www.google.com", "142.250.183.100", 443),
    ("mail.google.com", "142.250.183.101", 443),
    ("github.com", "140.82.112.4", 443),
    ("api.github.com", "140.82.112.6", 443),
    ("slack.com", "3.94.122.23", 443),
    ("zoom.us", "170.114.52.2", 443),
    ("www.salesforce.com", "13.110.54.35", 443),
    ("atlassian.net", "104.192.142.10", 443),
    ("aws.amazon.com", "52.94.236.248", 443),
    ("update.microsoft.com", "13.107.4.50", 443),
    ("cdn.jsdelivr.net", "104.16.18.35", 443),
    ("stackoverflow.com", "151.101.1.69", 443),
    ("www.linkedin.com", "13.107.42.14", 443),
    ("onedrive.live.com", "13.107.136.9", 443),
    ("docs.google.com", "142.250.183.110", 443),
    ("registry.npmjs.org", "104.16.24.35", 443),
    ("pypi.org", "151.101.0.223", 443),
]

USER_PROCESSES = [
    ("outlook.exe", "explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
    ("winword.exe", "explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    ("excel.exe", "explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
    ("chrome.exe", "explorer.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    ("msedge.exe", "explorer.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ("teams.exe", "explorer.exe", r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe"),
    ("explorer.exe", "userinit.exe", r"C:\Windows\explorer.exe"),
    ("onedrive.exe", "explorer.exe", r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
    ("code.exe", "explorer.exe", r"C:\Users\{u}\AppData\Local\Programs\Microsoft VS Code\Code.exe"),
    ("notepad.exe", "explorer.exe", r"C:\Windows\System32\notepad.exe"),
    ("acrord32.exe", "explorer.exe", r"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"),
    ("svchost.exe", "services.exe", r"C:\Windows\System32\svchost.exe"),
    ("searchindexer.exe", "services.exe", r"C:\Windows\System32\SearchIndexer.exe"),
    ("msmpeng.exe", "services.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe"),
]
DEV_PROCESSES = [
    ("git.exe", "code.exe", r"C:\Program Files\Git\cmd\git.exe", "git pull origin main"),
    ("node.exe", "code.exe", r"C:\Program Files\nodejs\node.exe", "node scripts/build.js"),
    ("python.exe", "code.exe", r"C:\Python312\python.exe", "python -m pytest tests/"),
    ("powershell.exe", "code.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File .\\build.ps1"),
    ("docker.exe", "powershell.exe", r"C:\Program Files\Docker\Docker\resources\bin\docker.exe", "docker compose up -d"),
    ("cmd.exe", "code.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c npm run test"),
    ("7z.exe", "explorer.exe", r"C:\Program Files\7-Zip\7z.exe", "7z.exe a -mx=5 release.zip .\\dist"),
]
IT_ADMIN_PROCESSES = [
    ("powershell.exe", "explorer.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -File C:\\Scripts\\Get-PatchStatus.ps1"),
    ("mmc.exe", "explorer.exe", r"C:\Windows\System32\mmc.exe", "mmc.exe dsa.msc"),
    ("schtasks.exe", "cmd.exe", r"C:\Windows\System32\schtasks.exe", "schtasks /create /tn NightlyBackup /tr \"C:\\Program Files\\Veeam\\backup.exe\" /sc daily /st 23:00"),
    ("ipconfig.exe", "cmd.exe", r"C:\Windows\System32\ipconfig.exe", "ipconfig /all"),
    ("net.exe", "cmd.exe", r"C:\Windows\System32\net.exe", "net user newhire01 /add /domain"),
    ("ping.exe", "cmd.exe", r"C:\Windows\System32\PING.EXE", "ping DC-01"),
    ("gpupdate.exe", "cmd.exe", r"C:\Windows\System32\gpupdate.exe", "gpupdate /force"),
]
DOC_DIRS = [r"C:\Users\{u}\Documents", r"C:\Users\{u}\Downloads", r"\\FS-01\shared\{d}", r"C:\Users\{u}\OneDrive - Corp"]
DOC_EXT = [".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".csv", ".md", ".json"]


@dataclass
class User:
    name: str
    department: str
    host: str
    ip: str
    is_admin: bool = False
    is_dev: bool = False
    traveller: bool = False
    travel_countries: list[str] = field(default_factory=list)
    start_hour: float = 9.0  # local-ish hour user typically logs in
    end_hour: float = 18.0


@dataclass
class Server:
    name: str
    ip: str
    role: str  # dc | file | db | api | web | vpn | proxy | dns | backup


@dataclass
class Enterprise:
    seed: int = 7
    n_users: int = 60
    users: list[User] = field(default_factory=list)
    servers: list[Server] = field(default_factory=list)
    domain: str = "corp.aegislab.local"

    def __post_init__(self) -> None:
        rng = random.Random(self.seed)
        names = FIRST_NAMES[: self.n_users]
        for i, n in enumerate(names):
            dept = DEPARTMENTS[i % len(DEPARTMENTS)]
            is_dev = dept == "engineering"
            is_admin = dept == "it"
            uname = f"adm-{n}" if is_admin and i % 2 == 0 else n
            self.users.append(
                User(
                    name=uname,
                    department=dept,
                    host=f"WS-{i + 1:03d}" if i % 5 else f"LT-{i + 1:03d}",
                    ip=f"10.0.{1 + i // 200}.{10 + i % 200}",
                    is_admin=is_admin,
                    is_dev=is_dev,
                    traveller=rng.random() < 0.15,
                    travel_countries=rng.sample(TRAVEL_COUNTRIES, k=2),
                    start_hour=round(rng.uniform(8.0, 10.5), 2),
                    end_hour=round(rng.uniform(17.0, 19.5), 2),
                )
            )
        self.servers = [
            Server("DC-01", "10.0.2.10", "dc"),
            Server("DC-02", "10.0.2.11", "dc"),
            Server("FS-01", "10.0.2.20", "file"),
            Server("DB-01", "10.0.2.30", "db"),
            Server("API-01", "10.0.2.40", "api"),
            Server("WEB-01", "10.0.2.41", "web"),
            Server("VPN-01", "10.0.2.50", "vpn"),
            Server("PRX-01", "10.0.2.60", "proxy"),
            Server("DNS-01", "10.0.2.53", "dns"),
            Server("BKP-01", "10.0.2.70", "backup"),
        ]

    # ------------------------------------------------------------------ helpers
    def user(self, name: str) -> User:
        return next(u for u in self.users if u.name == name)

    def server(self, role: str) -> Server:
        return next(s for s in self.servers if s.role == role)

    def host_ip(self, host: str) -> str:
        for u in self.users:
            if u.host == host:
                return u.ip
        for s in self.servers:
            if s.name == host:
                return s.ip
        return "10.0.9.9"

    def random_user(self, rng: random.Random, *, admin: bool | None = None, dev: bool | None = None) -> User:
        pool = [
            u
            for u in self.users
            if (admin is None or u.is_admin == admin) and (dev is None or u.is_dev == dev)
        ]
        return rng.choice(pool or self.users)

    def workstations(self) -> list[str]:
        return [u.host for u in self.users]

    def summary(self) -> dict:
        return {
            "users": len(self.users),
            "admins": sum(u.is_admin for u in self.users),
            "developers": sum(u.is_dev for u in self.users),
            "travellers": sum(u.traveller for u in self.users),
            "workstations": len(self.users),
            "servers": [s.name for s in self.servers],
            "departments": DEPARTMENTS,
        }
