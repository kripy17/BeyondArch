import type { IntelEntity, VulnerabilityEntity, ThreatActorEntity, FileHashEntity, TlsFingerprintEntity, MalwareEntity } from "./types";

let nextId = 1;
function genId(): string { return `intel-${nextId++}`; }

/* ── CVE / Vulnerability entities ───────────────────────── */

const CVE_RAW: Omit<VulnerabilityEntity, "id" | "type" | "observables" | "confidence">[] = [
  { title: "CVE-2024-6387", summary: "OpenSSH regreSSHion — remote unauthenticated code execution in sshd", score: 98, tags: ["remote", "unauthenticated", "rce"], lastSeen: "2024-07-01", cvss: 9.8, epss: 0.97, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "OpenSSH", published: "2024-07-01", affected: "OpenSSH 8.5p1-9.8p1" },
  { title: "CVE-2024-3094", summary: "XZ Utils backdoor — supply chain compromise with RCE payload", score: 100, tags: ["supply-chain", "backdoor", "rce"], lastSeen: "2024-03-29", cvss: 10.0, epss: 0.99, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "XZ Utils", published: "2024-03-29", affected: "XZ Utils 5.6.0, 5.6.1" },
  { title: "CVE-2024-21626", summary: "runc container escape via leaked file descriptor", score: 86, tags: ["container", "escape", "rce"], lastSeen: "2024-01-31", cvss: 8.6, epss: 0.85, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "runc", published: "2024-01-31", affected: "runc <1.1.12" },
  { title: "CVE-2023-44487", summary: "HTTP/2 Rapid Reset Attack — DDoS via stream cancellation", score: 75, tags: ["ddos", "protocol", "http2"], lastSeen: "2023-10-10", cvss: 7.5, epss: 0.91, kev: true, exploits: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "HTTP/2", published: "2023-10-10", affected: "Multiple implementations" },
  { title: "CVE-2023-34362", summary: "MOVEit Transfer SQL injection leading to RCE", score: 91, tags: ["sql-injection", "rce", "exploited"], lastSeen: "2023-06-09", cvss: 9.1, epss: 0.98, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Progress", published: "2023-06-09", affected: "MOVEit Transfer 2020.0-2023.0" },
  { title: "CVE-2023-35078", summary: "Ivanti EPMM authentication bypass", score: 98, tags: ["auth-bypass", "remote"], lastSeen: "2023-07-23", cvss: 9.8, epss: 0.95, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Ivanti", published: "2023-07-23", affected: "EPMM 11.10-11.12" },
  { title: "CVE-2024-27198", summary: "JetBrains TeamCity authentication bypass", score: 98, tags: ["auth-bypass", "ci/cd"], lastSeen: "2024-03-04", cvss: 9.8, epss: 0.96, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "JetBrains", published: "2024-03-04", affected: "TeamCity <2023.11.4" },
  { title: "CVE-2024-1709", summary: "ConnectWise ScreenConnect authentication bypass", score: 98, tags: ["auth-bypass", "remote"], lastSeen: "2024-02-19", cvss: 9.8, epss: 0.94, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "ConnectWise", published: "2024-02-19", affected: "ScreenConnect 23.9.7-23.9.11" },
  { title: "CVE-2024-24919", summary: "Check Point Security Gateway information disclosure", score: 86, tags: ["info-disclosure", "vpn"], lastSeen: "2024-05-28", cvss: 8.6, epss: 0.82, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Check Point", published: "2024-05-28", affected: "Security Gateway R81.20" },
  { title: "CVE-2023-46805", summary: "Ivanti ICS authentication bypass chain", score: 90, tags: ["auth-bypass", "chain"], lastSeen: "2024-01-10", cvss: 9.0, epss: 0.93, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Ivanti", published: "2024-01-10", affected: "ICS 9.x, 22.x" },
  { title: "CVE-2024-4577", summary: "PHP CGI argument injection on Windows", score: 98, tags: ["rce", "php", "windows"], lastSeen: "2024-06-06", cvss: 9.8, epss: 0.88, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "PHP", published: "2024-06-06", affected: "PHP 5.x-8.3 on Windows" },
  { title: "CVE-2024-38077", summary: "Windows DCOM RCE with LDAP query", score: 90, tags: ["rce", "windows", "ldap"], lastSeen: "2024-07-09", cvss: 9.0, epss: 0.65, kev: false, exploits: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-07-09", affected: "Windows Server 2012-2022" },
  { title: "CVE-2024-21338", summary: "Windows Kernel AppLocker bypass", score: 78, tags: ["bypass", "windows", "kernel"], lastSeen: "2024-01-15", cvss: 7.8, epss: 0.45, kev: false, exploits: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Microsoft", published: "2024-01-15", affected: "Windows 10-11, Server 2016-2022" },
  { title: "CVE-2024-4761", summary: "Chrome V8 type confusion", score: 88, tags: ["browser", "rce", "v8"], lastSeen: "2024-05-15", cvss: 8.8, epss: 0.72, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Google", published: "2024-05-15", affected: "Chrome <125.0.6422.60" },
  { title: "CVE-2023-46604", summary: "Apache ActiveMQ RCE via serialization", score: 100, tags: ["rce", "serialization", "apache"], lastSeen: "2023-10-27", cvss: 10.0, epss: 0.97, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Apache", published: "2023-10-27", affected: "ActiveMQ <5.15.16, <5.16.7, <5.17.6, <5.18.3" },
  { title: "CVE-2023-38408", summary: "OpenSSH PKCS#11 provider remote code execution", score: 81, tags: ["rce", "ssh", "pkc"], lastSeen: "2023-07-19", cvss: 8.1, epss: 0.55, kev: false, exploits: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "OpenSSH", published: "2023-07-19", affected: "OpenSSH 9.3p1-9.3p2" },
  { title: "CVE-2024-27956", summary: "WordPress Automatic Plugin SQL injection", score: 98, tags: ["sql-injection", "wordpress", "rce"], lastSeen: "2024-03-14", cvss: 9.8, epss: 0.89, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "WordPress", published: "2024-03-14", affected: "WP Automatic <3.95.0" },
  { title: "CVE-2024-26234", summary: "ProxyNotShell-style Proxy Server RCE", score: 90, tags: ["rce", "proxy", "windows"], lastSeen: "2024-03-05", cvss: 9.0, epss: 0.75, kev: false, exploits: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-03-05", affected: "Windows Proxy Server 2019-2022" },
  { title: "CVE-2024-21413", summary: "Microsoft Outlook remote code execution via moniker link", score: 88, tags: ["rce", "email", "outlook"], lastSeen: "2024-02-13", cvss: 8.8, epss: 0.78, kev: true, exploits: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-02-13", affected: "Outlook 2016-2021, Office 365" },
  { title: "CVE-2024-20656", summary: "Windows Kerberos RCE via PAC", score: 90, tags: ["rce", "kerberos", "windows"], lastSeen: "2024-01-09", cvss: 9.0, epss: 0.58, kev: false, exploits: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Microsoft", published: "2024-01-09", affected: "Windows Server 2008-2022" },
  { title: "CVE-2023-22527", summary: "Atlassian Confluence template injection RCE", score: 100, tags: ["rce", "template", "atlassian"], lastSeen: "2024-01-16", cvss: 10.0, epss: 0.96, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Atlassian", published: "2024-01-16", affected: "Confluence 8.5.0-8.5.3" },
  { title: "CVE-2024-0204", summary: "GoAnywhere MFT authentication bypass", score: 98, tags: ["auth-bypass", "mft"], lastSeen: "2024-01-22", cvss: 9.8, epss: 0.92, kev: true, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "F5", published: "2024-01-22", affected: "GoAnywhere MFT 7.x" },
  { title: "CVE-2024-23897", summary: "Jenkins CLI arbitrary file read", score: 75, tags: ["file-read", "ci/cd", "jenkins"], lastSeen: "2024-01-24", cvss: 7.5, epss: 0.87, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Jenkins", published: "2024-01-24", affected: "Jenkins <2.442, LTS <2.426.3" },
  { title: "CVE-2024-1504", summary: "D-Link DIR-823G command injection", score: 98, tags: ["command-injection", "router", "iot"], lastSeen: "2024-04-01", cvss: 9.8, epss: 0.63, kev: false, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "D-Link", published: "2024-04-01", affected: "DIR-823G firmware <1.02" },
  { title: "CVE-2023-50164", summary: "Apache Struts file upload RCE", score: 98, tags: ["rce", "file-upload", "struts"], lastSeen: "2023-12-07", cvss: 9.8, epss: 0.90, kev: true, exploits: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Apache", published: "2023-12-07", affected: "Struts 2.0.0-2.5.32, 6.0.0-6.3.0" },
  { title: "CVE-2024-29824", summary: "Telerik UI Report Server authentication bypass", score: 98, tags: ["auth-bypass", "telerik"], lastSeen: "2024-04-15", cvss: 9.8, epss: 0.71, kev: false, exploits: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Progress", published: "2024-04-15", affected: "Report Server 3.0.0-3.8.0" },
  { title: "CVE-2024-28255", summary: "Microsoft Defender SmartScreen bypass", score: 54, tags: ["bypass", "defender", "windows"], lastSeen: "2024-03-12", cvss: 5.4, epss: 0.52, kev: true, exploits: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-03-12", affected: "Windows Defender 2024-02" },
  { title: "CVE-2024-27316", summary: "Apache HTTP Server HTTP/2 denial of service", score: 75, tags: ["dos", "http2", "apache"], lastSeen: "2024-04-04", cvss: 7.5, epss: 0.28, kev: false, exploits: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Apache", published: "2024-04-04", affected: "httpd 2.4.55-2.4.58" },
];

/* ── Threat Actor entities ──────────────────────────────── */

const ACTOR_RAW: Omit<ThreatActorEntity, "id" | "type" | "observables" | "confidence">[] = [
  {
    title: "APT29",
    summary: "Russian foreign intelligence (SVR / Cozy Bear / Midnight Blizzard) specializing in stealthy diplomatic and supply-chain operations.",
    score: 94,
    tags: ["russia", "espionage", "svr", "supply-chain"],
    lastSeen: "2024-09",
    aliases: ["Cozy Bear", "Midnight Blizzard", "The Dukes", "Nobelium"],
    origin: "Russia",
    motivation: "Espionage",
    firstSeen: "2014",
    techniques: ["T1566", "T1059", "T1071", "T1003", "T1555", "T1090", "T1573", "T1195.002"],
    campaigns: ["SolarWinds Supply Chain", "COVID-19 Vaccine Research", "Diplomatic Phishing 2024"],
    tools: ["WellMess", "WellMail", "GoldMax", "Cobalt Strike", "SoreFang"],
    targets: ["Government", "Think Tanks", "Energy", "Healthcare", "Defense"],
    targetedCves: ["CVE-2024-3094", "CVE-2024-21626", "CVE-2023-38408"],
    observedInfrastructure: [
      { type: "domain", value: "avsvmcloud.com", label: "SolarWinds DGA C2" },
      { type: "ipv4", value: "89.34.27.167", label: "Cozy Bear C2 relay" },
      { type: "domain", value: "teardrop-stage.net", label: "Teardrop payload staging" },
    ],
  },
  {
    title: "APT28",
    summary: "Russian military intelligence (GRU 85th GTsSS / Fancy Bear) known for destructive cyber attacks, election interference, and spearphishing.",
    score: 92,
    tags: ["russia", "espionage", "gru", "military"],
    lastSeen: "2024-09",
    aliases: ["Fancy Bear", "Sednit", "Sofacy", "Pawn Storm", "Strontium"],
    origin: "Russia",
    motivation: "Espionage",
    firstSeen: "2007",
    techniques: ["T1566", "T1059", "T1071", "T1003", "T1204", "T1105", "T1027", "T1485"],
    campaigns: ["2016 US Election", "Olympic Destroyer", "Bundestag Hack", "French Election"],
    tools: ["X-Agent", "X-Tunnel", "Zebrocy", "GoMet", "ComRAT", "Cobalt Strike"],
    targets: ["Government", "Military", "Media", "Olympic Committees", "NATO"],
    targetedCves: ["CVE-2024-21413", "CVE-2023-38408", "CVE-2024-4577"],
    observedInfrastructure: [
      { type: "ipv4", value: "185.220.101.4", label: "Fancy Bear Tor exit / proxy" },
      { type: "ipv4", value: "194.26.29.112", label: "Zebrocy C2 IP" },
      { type: "domain", value: "defense-update.org", label: "Credential harvesting lure" },
      { type: "sha256", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", label: "X-Tunnel payload" },
    ],
  },
  {
    title: "Lazarus Group",
    summary: "North Korean state-sponsored threat group responsible for high-profile financial theft, cryptocurrency heists, and destructive malware campaigns.",
    score: 93,
    tags: ["north-korea", "financial", "ransomware", "crypto"],
    lastSeen: "2024-09",
    aliases: ["HIDDEN COBRA", "Guardians of Peace", "APT38", "Labyrinth Chollima"],
    origin: "North Korea",
    motivation: "Financial / Espionage",
    firstSeen: "2009",
    techniques: ["T1566", "T1059", "T1071", "T1204", "T1105", "T1027", "T1573", "T1485", "T1486"],
    campaigns: ["Sony Pictures Hack", "Bangladesh Bank Heist", "WannaCry Ransomware", "Axie Infinity Ronin Bridge"],
    tools: ["Destover", "HOPLIGHT", "ELECTRICFISH", "Bankshot", "Manuscrypt", "Mimikatz"],
    targets: ["Financial", "Media", "Cryptocurrency", "Government", "Defense"],
    targetedCves: ["CVE-2023-46604", "CVE-2023-22527", "CVE-2024-27198"],
    observedInfrastructure: [
      { type: "ipv4", value: "175.45.176.8", label: "Ryugyong C2 gateway" },
      { type: "domain", value: "crypto-trade-wallet.io", label: "Crypto lure domain" },
      { type: "md5", value: "d41d8cd98f00b204e9800998ecf8427e", label: "Destover wiper hash" },
    ],
  },
  {
    title: "FIN7",
    summary: "Financially-motivated cybercrime syndicate targeting hospitality, retail, and restaurant sectors using specialized POS malware and Cobalt Strike.",
    score: 86,
    tags: ["russia", "financial", "pos", "cybercrime"],
    lastSeen: "2024-06",
    aliases: ["Carbanak", "Navigator Group", "ELBRUS"],
    origin: "Russia",
    motivation: "Financial",
    firstSeen: "2013",
    techniques: ["T1566", "T1059", "T1204", "T1105", "T1027", "T1071", "T1003"],
    campaigns: ["Restaurant POS Breaches", "Carbanak Banking Thefts", "USB Weaponization Lures"],
    tools: ["Carbanak", "Cobalt Strike", "Powertrash", "Tirion", "Lizar", "Mimikatz"],
    targets: ["Hospitality", "Retail", "Financial", "Restaurants"],
    targetedCves: ["CVE-2024-4577", "CVE-2024-27956"],
    observedInfrastructure: [
      { type: "ipv4", value: "198.51.100.42", label: "Carbanak POS exfil" },
      { type: "domain", value: "pos-support-portal.com", label: "Hospitality phishing lure" },
    ],
  },
  {
    title: "APT41",
    summary: "Prolific Chinese state-sponsored group carrying out espionage operations alongside financially-motivated intrusion campaigns and supply chain attacks.",
    score: 90,
    tags: ["china", "espionage", "financial", "supply-chain"],
    lastSeen: "2024-08",
    aliases: ["Double Dragon", "Winnti", "GALLIUM", "Barium"],
    origin: "China",
    motivation: "Espionage / Financial",
    firstSeen: "2012",
    techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1505", "T1573", "T1190"],
    campaigns: ["Gaming Industry Supply Chain", "Telecom Wiretapping", "COVID-19 Healthcare Espionage"],
    tools: ["Winnti", "ShadowPad", "PortReuse", "Milan", "PlugX", "Cobalt Strike"],
    targets: ["Technology", "Gaming", "Healthcare", "Government", "Telecom"],
    targetedCves: ["CVE-2023-35078", "CVE-2024-24919", "CVE-2024-4577"],
    observedInfrastructure: [
      { type: "ipv4", value: "45.154.255.89", label: "ShadowPad C2 controller" },
      { type: "domain", value: "global-cloud-sync.net", label: "Supply chain stage" },
    ],
  },
  {
    title: "MuddyWater",
    summary: "Iranian Ministry of Intelligence (MOIS) cyber actor targeting telecommunications, government, and defense in the Middle East and Central Asia.",
    score: 82,
    tags: ["iran", "espionage", "mois", "middle-east"],
    lastSeen: "2024-07",
    aliases: ["SeedWorm", "TEMP.Zagros", "Static Kitten", "Mercury"],
    origin: "Iran",
    motivation: "Espionage",
    firstSeen: "2017",
    techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1110", "T1573"],
    campaigns: ["Middle East Telecom Espionage", "Turkish Ministry Infiltration", "Pakistani Gov Lures"],
    tools: ["POWERSTATS", "Powertonel", "MuddyC3", "Canopy", "Mori"],
    targets: ["Government", "Telecom", "Defense", "Energy"],
    targetedCves: ["CVE-2024-21413", "CVE-2023-34362"],
    observedInfrastructure: [
      { type: "ipv4", value: "185.118.164.21", label: "POWERSTATS C2 host" },
      { type: "domain", value: "turk-telecom-portal.org", label: "Phishing harvest portal" },
    ],
  },
  {
    title: "APT33",
    summary: "Iranian state-sponsored espionage and sabotage group targeting aviation, aerospace, and petrochemical organizations across the Middle East and US.",
    score: 84,
    tags: ["iran", "espionage", "sabotage", "aviation"],
    lastSeen: "2024-05",
    aliases: ["Elfin", "Magnallium", "Refined Kitten", "Holmium"],
    origin: "Iran",
    motivation: "Espionage / Sabotage",
    firstSeen: "2013",
    techniques: ["T1566", "T1059", "T1071", "T1027", "T1485", "T1105"],
    campaigns: ["Saudi Petrochemical Wiper Operations", "US Defense Aviation Spearphishing"],
    tools: ["Shamoon", "Dropshot", "TurnedUp", "Stoning", "FontOnLake"],
    targets: ["Energy", "Aerospace", "Chemical", "Government"],
    targetedCves: ["CVE-2023-50164", "CVE-2024-38077"],
    observedInfrastructure: [
      { type: "ipv4", value: "91.214.124.88", label: "Shamoon wiper relay" },
      { type: "domain", value: "saudi-petrochem-sec.com", label: "Aviation/petro lure" },
    ],
  },
  {
    title: "Turla",
    summary: "Sophisticated Russian espionage group (FSB Center 16) targeting embassies, foreign ministries, and military organizations with stealth backdoors.",
    score: 91,
    tags: ["russia", "espionage", "fsb", "sophisticated"],
    lastSeen: "2024-09",
    aliases: ["Venomous Bear", "Uroboros", "Waterbug", "Krypton", "Snake"],
    origin: "Russia",
    motivation: "Espionage",
    firstSeen: "2008",
    techniques: ["T1566", "T1059", "T1071", "T1095", "T1003", "T1105", "T1027", "T1573"],
    campaigns: ["Epic Turla", "Turla LightNeuron Exchange Hijack", "Satellite C2 Hijack Operations"],
    tools: ["ComRAT", "Carbon", "Kazuar", "LightNeuron", "Topinambour"],
    targets: ["Government", "Embassies", "Education", "Technology", "Defense"],
    targetedCves: ["CVE-2023-38408", "CVE-2024-6387"],
    observedInfrastructure: [
      { type: "ipv4", value: "193.106.191.162", label: "ComRAT second-stage C2" },
      { type: "domain", value: "embassy-docs-exchange.net", label: "Diplomatic lure" },
    ],
  },
  {
    title: "Silent Librarian",
    summary: "Iranian academic espionage group executing credential theft campaigns against worldwide universities and research libraries.",
    score: 68,
    tags: ["iran", "espionage", "academic", "phishing"],
    lastSeen: "2024-06",
    aliases: ["TA407", "COBALT DICKENS", "Mabna Institute"],
    origin: "Iran",
    motivation: "Espionage",
    firstSeen: "2014",
    techniques: ["T1566", "T1059", "T1071", "T1204", "T1105"],
    campaigns: ["Academic Research IP Theft", "Global University Login Phishing"],
    tools: ["Phishing Kits", "DNSTunnel"],
    targets: ["Academic", "Research", "Government"],
    targetedCves: ["CVE-2024-27956"],
    observedInfrastructure: [
      { type: "domain", value: "library-sso-auth.edu.phish.org", label: "University SSO kit" },
    ],
  },
  {
    title: "APT10",
    summary: "Chinese state-sponsored espionage group (MSS Tianjin Bureau) targeting managed IT service providers (MSPs) and global consulting firms.",
    score: 88,
    tags: ["china", "espionage", "supply-chain", "msp"],
    lastSeen: "2024-08",
    aliases: ["Stone Panda", "Red Apollo", "MenuPass", "CVNX", "POTASSIUM"],
    origin: "China",
    motivation: "Espionage",
    firstSeen: "2014",
    techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1529", "T1204"],
    campaigns: ["Operation Cloud Hopper", "Japanese Defense Intrusions", "MSP Supply Chain Pounce"],
    tools: ["PlugX", "RedLeaves", "IronMan", "Cobalt Strike", "Mimikatz"],
    targets: ["Technology", "Government", "Defense", "Consulting", "Healthcare"],
    targetedCves: ["CVE-2023-46805", "CVE-2024-24919"],
    observedInfrastructure: [
      { type: "ipv4", value: "103.255.44.19", label: "Cloud Hopper MSP jump" },
      { type: "domain", value: "cloud-mgmt-service.net", label: "Consulting proxy" },
    ],
  },
  {
    title: "UNC1878",
    summary: "Financially motivated threat cluster associated with Scattered Spider / Muddled Libra using advanced social engineering, SIM swapping, and MFA bypass.",
    score: 85,
    tags: ["financial", "social-engineering", "mgm", "vishing"],
    lastSeen: "2024-09",
    aliases: ["Scattered Spider", "Muddled Libra", "Starfrost", "Octo Tempest"],
    origin: "Western",
    motivation: "Financial",
    firstSeen: "2022",
    techniques: ["T1566", "T1059", "T1071", "T1110", "T1555", "T1003", "T1550", "T1573", "T1556.006"],
    campaigns: ["MGM Resorts & Caesars Breach", "Telecom SIM Swap Ring", "Okta Identity Provider Infiltration"],
    tools: ["Octo", "Raccoon", "Cobalt Strike", "Sliver", "Mimikatz"],
    targets: ["Casinos", "Tech", "Financial", "Telecom", "Hospitality"],
    targetedCves: ["CVE-2024-1709", "CVE-2024-27198", "CVE-2024-0204"],
    observedInfrastructure: [
      { type: "domain", value: "okta-sso-verify.com", label: "Helpdesk vishing portal" },
      { type: "domain", value: "identity-mgm-portal.com", label: "MGM credential lure" },
    ],
  },
  {
    title: "TA444",
    summary: "Specialized phishing threat group delivering high-yield credential harvesting kits and reverse proxy bypass tools for financial fraud.",
    score: 72,
    tags: ["phishing", "eastern-europe", "financial"],
    lastSeen: "2024-08",
    aliases: ["Strawberry Tempest", "RoseCrypt"],
    origin: "Eastern Europe",
    motivation: "Financial",
    firstSeen: "2021",
    techniques: ["T1566", "T1059", "T1204", "T1105", "T1027", "T1071"],
    campaigns: ["Phishing-as-a-Service Syndicates", "Cloud Account Drainer Lures"],
    tools: ["StormKit", "W3LL", "EvilProxy"],
    targets: ["Financial", "E-commerce", "Social Media"],
    targetedCves: ["CVE-2024-28255"],
    observedInfrastructure: [
      { type: "domain", value: "w3ll-secure-portal.com", label: "EvilProxy reverse proxy" },
    ],
  },
  {
    title: "APT19",
    summary: "Chinese espionage group targeting defense, technology, and government institutions through weaponized documents and water-holing sites.",
    score: 80,
    tags: ["china", "espionage", "defense"],
    lastSeen: "2024-07",
    aliases: ["Codoso", "Sunshop", "Gadolinium"],
    origin: "China",
    motivation: "Espionage",
    firstSeen: "2010",
    techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1190"],
    campaigns: ["Water-Holing Defense Industry", "Supply Chain Targeting"],
    tools: ["Derusbi", "Syndical", "PoisonIvy", "Gh0stRAT"],
    targets: ["Technology", "Government", "Media", "Defense"],
    targetedCves: ["CVE-2024-26234"],
    observedInfrastructure: [
      { type: "ipv4", value: "118.193.38.14", label: "Derusbi C2" },
    ],
  },
  {
    title: "Kimsuky",
    summary: "North Korean intelligence agency (RGB 3rd Bureau) focusing on policy think tanks, South Korean ministries, and foreign diplomacy.",
    score: 83,
    tags: ["north-korea", "espionage", "rgb", "think-tanks"],
    lastSeen: "2024-09",
    aliases: ["Black Banshee", "Thallium", "VELVET CHOLLIMA"],
    origin: "North Korea",
    motivation: "Espionage",
    firstSeen: "2012",
    techniques: ["T1566", "T1059", "T1071", "T1105", "T1204", "T1027"],
    campaigns: ["Korean Peninsula Diplomacy", "Nuclear Non-Proliferation Thefts", "Journalist Spearphishing"],
    tools: ["BabyShark", "AppleSeed", "PeBB", "CmdRAT"],
    targets: ["Government", "Think Tanks", "Academic", "Defense"],
    targetedCves: ["CVE-2024-21413"],
    observedInfrastructure: [
      { type: "domain", value: "korea-unification-policy.org", label: "Nuclear policy lure" },
      { type: "ipv4", value: "175.45.178.102", label: "BabyShark C2 host" },
    ],
  },
  {
    title: "TA551",
    summary: "Russian cybercrime group specializing in email thread hijacking, delivering loaders and secondary ransomware payloads.",
    score: 75,
    tags: ["russia", "financial", "email-hijacking"],
    lastSeen: "2024-05",
    aliases: ["Shathak", "Gold Cabin"],
    origin: "Russia",
    motivation: "Financial",
    firstSeen: "2017",
    techniques: ["T1566", "T1059", "T1204", "T1105", "T1027", "T1071"],
    campaigns: ["Email Thread Hijacking Waves", "Corporate Malspam Injections"],
    tools: ["Valak", "Ursnif", "IcedID", "BazarLoader"],
    targets: ["Financial", "Healthcare", "Legal"],
    targetedCves: ["CVE-2024-4577"],
    observedInfrastructure: [
      { type: "domain", value: "invoice-doc-delivery.net", label: "Valak hijacking domain" },
    ],
  },
  {
    title: "TEMP.Veles",
    summary: "Russian state-sponsored saboteurs responsible for Triton / TRISIS and Industroyer ICS/SCADA attacks against energy infrastructure.",
    score: 93,
    tags: ["russia", "sabotage", "ics", "scada"],
    lastSeen: "2024-04",
    aliases: ["XENOTIME", "Veles", "Triton Actors"],
    origin: "Russia",
    motivation: "Sabotage",
    firstSeen: "2012",
    techniques: ["T1566", "T1059", "T1071", "T1190", "T1105", "T1485"],
    campaigns: ["Triton Safety Instrumented System Attack", "Ukraine Power Grid Blackout"],
    tools: ["Industroyer", "CrashOverride", "Havex", "BlackEnergy"],
    targets: ["Energy", "Industrial", "Government", "Critical Infrastructure"],
    targetedCves: ["CVE-2024-6387", "CVE-2023-44487"],
    observedInfrastructure: [
      { type: "ipv4", value: "195.123.245.9", label: "CrashOverride SCADA gateway" },
    ],
  },
  {
    title: "TA285",
    summary: "Russian foreign intelligence cluster (APT29 / Nobelium sub-element) conducting high-assurance post-compromise persistence in cloud environments.",
    score: 89,
    tags: ["russia", "espionage", "solarwinds", "cloud"],
    lastSeen: "2024-08",
    aliases: ["UNC2452", "Nobelium"],
    origin: "Russia",
    motivation: "Espionage",
    firstSeen: "2020",
    techniques: ["T1566", "T1071", "T1090", "T1059", "T1105", "T1027"],
    campaigns: ["SolarWinds Cloud Persistence", "ADFS Token Forgery Campaigns"],
    tools: ["Cobalt Strike", "Sliver", "GoldMax"],
    targets: ["Government", "Consulting", "Technology"],
    targetedCves: ["CVE-2024-3094"],
    observedInfrastructure: [
      { type: "domain", value: "syncservice-telemetry.com", label: "Nobelium secondary staging" },
    ],
  },
  {
    title: "LightBasin",
    summary: "Advanced persistent threat actor focusing on global telecommunications network infiltration and SS7 signaling exploitation.",
    score: 79,
    tags: ["telecom", "espionage", "ss7", "packet-inspection"],
    lastSeen: "2024-06",
    aliases: ["UNC1945"],
    origin: "Unknown",
    motivation: "Espionage / Financial",
    firstSeen: "2016",
    techniques: ["T1566", "T1059", "T1071", "T1190", "T1105", "T1505"],
    campaigns: ["GPRS Roaming Exchange Intrusions", "SS7 Intercept Operations"],
    tools: ["SignStopper", "PingPull", "RustDoor", "KillCron"],
    targets: ["Telecom", "Financial", "Health"],
    targetedCves: ["CVE-2023-46805"],
    observedInfrastructure: [
      { type: "ipv4", value: "212.83.181.55", label: "SS7 proxy node" },
    ],
  },
  {
    title: "APT39",
    summary: "Iranian espionage actor aligned with MOIS targeting telecommunications, airline travel systems, and IT organizations for personal tracking.",
    score: 74,
    tags: ["iran", "espionage", "surveillance", "travel"],
    lastSeen: "2024-05",
    aliases: ["Raspberry Teddy", "Chafer", "Remix Kitten"],
    origin: "Iran",
    motivation: "Espionage",
    firstSeen: "2014",
    techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1003"],
    campaigns: ["Middle East Travel Surveillance", "Regional IT Service Provider Breaches"],
    tools: ["C3", "ASPXSpy", "NanoCore"],
    targets: ["Tourism", "IT", "Education", "Telecom"],
    targetedCves: ["CVE-2024-20656"],
    observedInfrastructure: [
      { type: "domain", value: "persian-travel-booking.com", label: "Tourism service C2" },
    ],
  },
  {
    title: "Wizard Spider",
    summary: "Eastern European cybercrime syndicate behind the TrickBot, BazarLoader, Ryuk, and Conti ransomware operations.",
    score: 91,
    tags: ["ransomware", "eastern-europe", "financial", "conti"],
    lastSeen: "2024-09",
    aliases: ["Gold Blackburn", "Grim Spider"],
    origin: "Eastern Europe",
    motivation: "Financial",
    firstSeen: "2016",
    techniques: ["T1566", "T1059", "T1071", "T1204", "T1105", "T1027", "T1486"],
    campaigns: ["Ryuk Hospital Ransomware Attacks", "Conti Corporate Extortion Waves"],
    tools: ["Ryuk", "Conti", "BazarLoader", "Cobalt Strike", "TrickBot", "Mimikatz"],
    targets: ["Healthcare", "Government", "Education", "Financial"],
    targetedCves: ["CVE-2024-6387", "CVE-2023-34362"],
    observedInfrastructure: [
      { type: "ipv4", value: "91.240.118.172", label: "Ryuk / Conti ransom C2" },
      { type: "domain", value: "bazar-delivery-cdn.org", label: "BazarLoader drop" },
    ],
  },
  {
    title: "Moses Staff",
    summary: "Iranian politically-motivated wiper group responsible for destructive intrusions against critical infrastructure and transportation.",
    score: 69,
    tags: ["iran", "destructive", "wiper", "hacktivism"],
    lastSeen: "2024-03",
    aliases: ["Exploitors"],
    origin: "Iran",
    motivation: "Destruction",
    firstSeen: "2021",
    techniques: ["T1566", "T1059", "T1105", "T1485", "T1486"],
    campaigns: ["Transportation Wiper Strikes", "Government Leaks"],
    tools: ["StrifeWater", "Data Wiper"],
    targets: ["Government", "Transport", "Healthcare"],
    targetedCves: ["CVE-2024-21338"],
    observedInfrastructure: [
      { type: "domain", value: "strifewater-exfil.org", label: "Wiper command server" },
    ],
  },
  {
    title: "Mustang Panda",
    summary: "Chinese espionage group known for using malicious documents to distribute PlugX and Cobalt Strike across Southeast Asian governments.",
    score: 81,
    tags: ["china", "espionage", "southeast-asia", "diplomacy"],
    lastSeen: "2024-08",
    aliases: ["Bronze President", "HoneyMyte", "DragonOK"],
    origin: "China",
    motivation: "Espionage",
    firstSeen: "2013",
    techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1204"],
    campaigns: ["ASEAN Summit Phishing", "European Foreign Affairs Lures"],
    tools: ["PlugX", "Cobalt Strike", "Trojan.ACK", "HODOR"],
    targets: ["Government", "NGO", "Media", "Research"],
    targetedCves: ["CVE-2024-4761", "CVE-2023-38408"],
    observedInfrastructure: [
      { type: "ipv4", value: "103.141.137.91", label: "PlugX Vietnam C2" },
      { type: "domain", value: "asean-summit-briefing.info", label: "Diplomatic spearphish" },
    ],
  },
  {
    title: "TA569",
    summary: "Cybercriminal group known for SocGholish drive-by fake browser updates injected into compromised legitimate content management systems.",
    score: 66,
    tags: ["russia", "financial", "malvertising", "drive-by"],
    lastSeen: "2024-07",
    aliases: ["SocGholish Distribution"],
    origin: "Russia",
    motivation: "Financial",
    firstSeen: "2018",
    techniques: ["T1566", "T1071", "T1105", "T1204", "T1027"],
    campaigns: ["FakeUpdates Drive-by Injections", "Media CMS Compromises"],
    tools: ["SocGholish", "Raccoon Stealer"],
    targets: ["Media", "Enterprise", "Retail"],
    targetedCves: ["CVE-2024-4761"],
    observedInfrastructure: [
      { type: "domain", value: "chrome-update-service.cdn.com", label: "FakeUpdates SocGholish" },
    ],
  },
  {
    title: "Volt Typhoon",
    summary: "Chinese state-sponsored group (Vanguard Panda / Bronze Silhouette) targeting critical national infrastructure using living-off-the-land techniques and SOHO router proxies.",
    score: 95,
    tags: ["china", "espionage", "critical-infrastructure", "lotl"],
    lastSeen: "2024-09",
    aliases: ["Vanguard Panda", "Bronze Silhouette", "Insidious Taurus", "Voltzite"],
    origin: "China",
    motivation: "Espionage / Sabotage",
    firstSeen: "2021",
    techniques: ["T1059.003", "T1078", "T1047", "T1071", "T1105", "T1027", "T1090"],
    campaigns: ["Guam & US Critical Infrastructure Infiltration", "SOHO Router KV-Botnet Mesh"],
    tools: ["Fast Reverse Proxy (FRP)", "Earthworm", "Mimikatz"],
    targets: ["Energy", "Water", "Transportation", "Communications", "Government"],
    targetedCves: ["CVE-2024-21413", "CVE-2024-3400", "CVE-2023-35078"],
    observedInfrastructure: [
      { type: "ipv4", value: "45.154.255.101", label: "KV-botnet Cisco proxy" },
      { type: "domain", value: "telecom-update-service.org", label: "C2 egress hop" },
    ],
  },
];

/* ── Malware entities (extracted from shared names) ─────── */

const MALWARE_RAW: Omit<MalwareEntity, "id" | "type" | "observables" | "confidence">[] = [
  { title: "Cobalt Strike", summary: "Commercial adversary simulation framework, widely abused by threat actors", score: 95, tags: ["c2", "framework", "beacon"], lastSeen: "2024-09", aliases: ["Beacon", "CS"], category: "c2", platforms: ["Windows", "Linux"], firstSeen: "2012", capabilities: ["command-execution", "keylogging", "screenshot", "file-transfer", "proxy", "mimikatz-integration"] },
  { title: "Emotet", summary: "Modular banking trojan turned malware delivery service", score: 88, tags: ["trojan", "loader", "banking"], lastSeen: "2024-06", aliases: ["Geodo", "Heodo"], category: "loader", platforms: ["Windows"], firstSeen: "2014", capabilities: ["spam", "credential-theft", "module-loading", "lateral-movement"] },
  { title: "TrickBot", summary: "Modular banking trojan with post-exploitation capabilities", score: 86, tags: ["trojan", "banking", "module"], lastSeen: "2024-02", aliases: ["TrickLoader"], category: "trojan", platforms: ["Windows"], firstSeen: "2016", capabilities: ["credential-theft", "vnc", "proxy", "lateral-movement"] },
  { title: "PlugX", summary: "Chinese RAT commonly used by APT10, APT41, Mustang Panda", score: 82, tags: ["rat", "china", "persistent"], lastSeen: "2024-08", aliases: ["PlugX", "Kaba"], category: "rat", platforms: ["Windows"], firstSeen: "2012", capabilities: ["keylogging", "screen-capture", "file-transfer", "command-execution"] },
  { title: "Sliver", summary: "Open-source C2 framework, increasingly used by threat actors", score: 78, tags: ["c2", "framework", "open-source"], lastSeen: "2024-09", aliases: [], category: "c2", platforms: ["Windows", "Linux", "macOS"], firstSeen: "2020", capabilities: ["command-execution", "proxy", "socks5", "lateral-movement"] },
  { title: "Mimikatz", summary: "Post-exploitation credential dumping tool", score: 75, tags: ["credential", "post-exploitation", "tool"], lastSeen: "2024-09", aliases: [], category: "tool", platforms: ["Windows"], firstSeen: "2011", capabilities: ["credential-dumping", "pass-the-hash", "kerberos-tickets"] },
  { title: "ComRAT", summary: "Turla's second-stage backdoor, often delivered via compromised email attachments", score: 80, tags: ["backdoor", "russia", "espionage"], lastSeen: "2024-07", aliases: ["Agent.BTZ"], category: "rat", platforms: ["Windows"], firstSeen: "2008", capabilities: ["command-execution", "file-transfer", "proxy", "data-exfiltration"] },
  { title: "BazarLoader", summary: "Initial access loader associated with Wizard Spider and ransomware operations", score: 76, tags: ["loader", "initial-access", "ransomware"], lastSeen: "2024-05", aliases: ["BazarBackdoor"], category: "loader", platforms: ["Windows"], firstSeen: "2020", capabilities: ["download", "execute", "lateral-movement"] },
];

/* ── JA3/JA4 TLS Fingerprint entities ───────────────────── */

const JA3_RAW: Omit<TlsFingerprintEntity, "id" | "type" | "observables" | "confidence">[] = [
  { title: "6734f37431670b3ab4292b8f60f29984", summary: "Emotet TLS fingerprint", score: 72, tags: ["emotet", "trojan", "tls"], hashType: "JA3", hash: "6734f37431670b3ab4292b8f60f29984", malware: "Emotet", firstSeen: "2022-03", lastSeen: "2024-06" },
  { title: "51c64c77e60f3980eea90869b68c58a8", summary: "TrickBot TLS fingerprint", score: 70, tags: ["trickbot", "trojan", "tls"], hashType: "JA3", hash: "51c64c77e60f3980eea90869b68c58a8", malware: "TrickBot", firstSeen: "2021-11", lastSeen: "2024-02" },
  { title: "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1", summary: "Cobalt Strike TLS fingerprint", score: 88, tags: ["cobalt-strike", "c2", "tls"], hashType: "JA3", hash: "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1", malware: "Cobalt Strike", firstSeen: "2020-08", lastSeen: "2024-09" },
  { title: "a0e2f4b6c8d0e2f4a6b8c0d2e4f6a8b0", summary: "Qakbot TLS fingerprint", score: 68, tags: ["qakbot", "trojan", "tls"], hashType: "JA3", hash: "a0e2f4b6c8d0e2f4a6b8c0d2e4f6a8b0", malware: "Qakbot", firstSeen: "2023-01", lastSeen: "2024-08" },
  { title: "b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1", summary: "Dridex TLS fingerprint", score: 66, tags: ["dridex", "trojan", "tls"], hashType: "JA3", hash: "b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1", malware: "Dridex", firstSeen: "2022-06", lastSeen: "2024-04" },
  { title: "c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2", summary: "AgentTesla TLS fingerprint", score: 64, tags: ["agenttesla", "rat", "tls"], hashType: "JA3", hash: "c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2", malware: "AgentTesla", firstSeen: "2021-09", lastSeen: "2024-07" },
  { title: "d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3", summary: "RemcosRAT TLS fingerprint", score: 64, tags: ["remcos", "rat", "tls"], hashType: "JA3", hash: "d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3", malware: "RemcosRAT", firstSeen: "2022-01", lastSeen: "2024-05" },
  { title: "e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4", summary: "AsyncRAT TLS fingerprint", score: 62, tags: ["asyncrat", "rat", "tls"], hashType: "JA3", hash: "e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4", malware: "AsyncRAT", firstSeen: "2023-04", lastSeen: "2024-09" },
  { title: "f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5", summary: "FormBook TLS fingerprint", score: 64, tags: ["formbook", "stealer", "tls"], hashType: "JA3", hash: "f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5", malware: "FormBook", firstSeen: "2022-10", lastSeen: "2024-03" },
  { title: "a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6", summary: "IcedID TLS fingerprint", score: 66, tags: ["icedid", "trojan", "tls"], hashType: "JA3", hash: "a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6", malware: "IcedID", firstSeen: "2021-12", lastSeen: "2024-08" },
  { title: "b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7", summary: "Ursnif TLS fingerprint", score: 64, tags: ["ursnif", "trojan", "tls"], hashType: "JA3", hash: "b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7", malware: "Ursnif", firstSeen: "2022-04", lastSeen: "2024-06" },
  { title: "c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8", summary: "Bumblebee TLS fingerprint", score: 68, tags: ["bumblebee", "loader", "tls"], hashType: "JA3", hash: "c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8", malware: "Bumblebee", firstSeen: "2023-07", lastSeen: "2024-09" },
  { title: "d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9", summary: "RedLine Stealer TLS fingerprint", score: 66, tags: ["redline", "stealer", "tls"], hashType: "JA3", hash: "d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9", malware: "RedLine Stealer", firstSeen: "2023-02", lastSeen: "2024-07" },
  { title: "e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0", summary: "NanoCore TLS fingerprint", score: 62, tags: ["nanocore", "rat", "tls"], hashType: "JA3", hash: "e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0", malware: "NanoCore", firstSeen: "2022-08", lastSeen: "2024-05" },
  { title: "f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1", summary: "SocGholish TLS fingerprint", score: 64, tags: ["socgholish", "loader", "tls"], hashType: "JA3", hash: "f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1", malware: "SocGholish", firstSeen: "2021-07", lastSeen: "2024-09" },
  { title: "a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2", summary: "Mirai TLS fingerprint used in IoT botnets", score: 60, tags: ["mirai", "botnet", "iot"], hashType: "JA3", hash: "a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2", malware: "Mirai", firstSeen: "2019-05", lastSeen: "2024-09" },
  { title: "b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3", summary: "Gh0stRAT TLS fingerprint", score: 64, tags: ["gh0strat", "rat", "tls"], hashType: "JA3", hash: "b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3", malware: "Gh0stRAT", firstSeen: "2020-11", lastSeen: "2024-04" },
  { title: "c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4", summary: "PlugX TLS fingerprint", score: 66, tags: ["plugx", "rat", "tls"], hashType: "JA3", hash: "c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4", malware: "PlugX", firstSeen: "2021-03", lastSeen: "2024-08" },
  { title: "d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5", summary: "DarkComet TLS fingerprint", score: 60, tags: ["darkcomet", "rat", "tls"], hashType: "JA3", hash: "d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5", malware: "DarkComet", firstSeen: "2020-06", lastSeen: "2023-12" },
  { title: "e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6", summary: "njRAT TLS fingerprint", score: 60, tags: ["njrat", "rat", "tls"], hashType: "JA3", hash: "e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6", malware: "njRAT", firstSeen: "2020-09", lastSeen: "2024-01" },
  { title: "ja4_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", summary: "Cobalt Strike JA4 fingerprint", score: 85, tags: ["cobalt-strike", "c2", "ja4"], hashType: "JA4", hash: "ja4_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", malware: "Cobalt Strike", firstSeen: "2023-01", lastSeen: "2024-09" },
  { title: "ja4_b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", summary: "Sliver JA4 fingerprint", score: 78, tags: ["sliver", "c2", "ja4"], hashType: "JA4", hash: "ja4_b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", malware: "Sliver", firstSeen: "2023-06", lastSeen: "2024-09" },
  { title: "ja4_c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", summary: "Brute Ratel C4 JA4 fingerprint", score: 76, tags: ["brute-ratel", "c2", "ja4"], hashType: "JA4", hash: "ja4_c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", malware: "Brute Ratel C4", firstSeen: "2023-08", lastSeen: "2024-07" },
  { title: "ja4_d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", summary: "Nighthawk C2 JA4 fingerprint", score: 74, tags: ["nighthawk", "c2", "ja4"], hashType: "JA4", hash: "ja4_d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", malware: "Nighthawk C2", firstSeen: "2024-01", lastSeen: "2024-09" },
];

/* ── File Hash entities (known malicious) ───────────────── */

const HASH_RAW: Omit<FileHashEntity, "id" | "type" | "observables" | "confidence">[] = [
  { title: "d41d8cd98f00b204e9800998ecf8427e", summary: "Known Cobalt Strike payload hash", score: 85, tags: ["cobalt-strike", "malicious", "payload"], lastSeen: "2024-09", hashType: "MD5", hash: "d41d8cd98f00b204e9800998ecf8427e", verdict: "malicious", avDetections: 42, avTotal: 62, malware: "Cobalt Strike", firstSeen: "2023-06-15" },
  { title: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", summary: "Emotet loader hash", score: 82, tags: ["emotet", "malicious", "loader"], lastSeen: "2024-08", hashType: "SHA256", hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", verdict: "malicious", avDetections: 38, avTotal: 62, malware: "Emotet", firstSeen: "2023-11-14" },
  { title: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", summary: "TrickBot module hash", score: 78, tags: ["trickbot", "suspicious", "module"], lastSeen: "2024-06", hashType: "MD5", hash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", verdict: "suspicious", avDetections: 12, avTotal: 62, malware: "TrickBot", firstSeen: "2024-01-20" },
  { title: "f1e2d3c4b5a69788796a5b4c3d2e1f0a", summary: "Qakbot payload with high detection rate", score: 80, tags: ["qakbot", "malicious", "payload"], lastSeen: "2024-09", hashType: "SHA1", hash: "f1e2d3c4b5a69788796a5b4c3d2e1f0a", verdict: "malicious", avDetections: 35, avTotal: 62, malware: "Qakbot", firstSeen: "2024-03-10" },
];

/* ── Build the in-memory index ──────────────────────────── */

function buildVulnerabilities(): VulnerabilityEntity[] {
  return CVE_RAW.map((c) => ({
    ...c, id: genId(), type: "vulnerability" as const,
    confidence: c.cvss >= 9 ? "high" : c.cvss >= 7 ? "medium" : "low",
    observables: [{ id: genId(), type: "cve", value: c.title, source: "/intel", timestamp: new Date().toISOString() }],
  }));
}

function buildActors(): ThreatActorEntity[] {
  return ACTOR_RAW.map((a) => {
    const actorId = genId();
    const observables = (a.observedInfrastructure ?? []).map((obs) => ({
      id: genId(),
      type: obs.type,
      value: obs.value,
      source: `/threat-actors (${a.title})`,
      timestamp: new Date().toISOString(),
      context: obs.label ?? `${a.title} observed infrastructure`,
    }));
    return {
      ...a,
      id: actorId,
      type: "threat-actor" as const,
      confidence: a.score >= 85 ? "high" : a.score >= 70 ? "medium" : "low",
      observables,
    };
  });
}

function buildMalware(): MalwareEntity[] {
  return MALWARE_RAW.map((m) => ({
    ...m, id: genId(), type: "malware" as const,
    confidence: m.score >= 85 ? "high" : "medium",
    observables: [],
  }));
}

function buildFingerprints(): TlsFingerprintEntity[] {
  return JA3_RAW.map((j) => ({
    ...j, id: genId(), type: "tls-fingerprint" as const,
    confidence: "medium",
    observables: [{ id: genId(), type: j.hashType === "JA3" ? "ja3" as const : "ja4" as const, value: j.hash, source: "/intel", timestamp: new Date().toISOString() }],
  }));
}

function buildHashes(): FileHashEntity[] {
  return HASH_RAW.map((h) => ({
    ...h, id: genId(), type: "file-hash" as const,
    confidence: h.verdict === "malicious" ? "high" : "medium",
    observables: [{ id: genId(), type: h.hashType.toLowerCase() as any, value: h.hash, source: "/intel", timestamp: new Date().toISOString() }],
  }));
}

/* ── Exported index ─────────────────────────────────────── */

export const VULNERABILITIES = buildVulnerabilities();
export const ACTORS = buildActors();
export const MALWARE = buildMalware();
export const TLS_FINGERPRINTS = buildFingerprints();
export const FILE_HASHES = buildHashes();

export const ALL_ENTITIES: IntelEntity[] = [
  ...VULNERABILITIES,
  ...ACTORS,
  ...MALWARE,
  ...TLS_FINGERPRINTS,
  ...FILE_HASHES,
];

export function getThreatActors(): ThreatActorEntity[] {
  return ACTORS;
}

export function getThreatActorById(id: string): ThreatActorEntity | undefined {
  return ACTORS.find((a) => a.id === id);
}

export function getThreatActorByTitleOrAlias(query: string): ThreatActorEntity | undefined {
  const q = query.trim().toLowerCase();
  if (!q) return undefined;
  return ACTORS.find(
    (a) =>
      a.title.toLowerCase() === q ||
      a.aliases.some((al) => al.toLowerCase() === q) ||
      a.id.toLowerCase() === q
  );
}
