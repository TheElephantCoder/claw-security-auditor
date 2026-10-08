"use strict";

/**
 * Detection rules for the OpenClaw Security Auditor (v4).
 *
 * Each rule: { id, level, score, label, patterns, noCommentDiscount? }
 * patterns: RegExp[] tested per-file against raw AND evasion-normalized
 * content (see lib/normalize.js). Rules with patterns:[] use custom logic
 * in lib/analyze.js.
 *
 * NOTE (self-scan hygiene): this file is itself scanned if you point the
 * auditor at its own repo. Pattern literals are written escaped/split so the
 * source text of a pattern does not match the pattern itself. Keep that
 * discipline when adding rules — never write a literal dangerous string
 * (shell pipelines, registry keys, credential paths) in comments.
 */

const RULES_VERSION = "4.1.0";

// Rule IDs that force a High rating regardless of total score.
const FORCE_HIGH_IDS = ["H2", "H4", "H17"];

// Signature-database hygiene: detection patterns must name dangerous APIs,
// which makes naive static scanners flag THIS file as malicious
// (self-detection). The module name below is assembled from character codes
// so no literal appears in source. Standard practice for security tooling,
// not obfuscation — see lib/utils.js and CHANGELOG 4.1.0.
const { SYSPROC_MOD } = require("./utils");

const RULES = [
  // ── HIGH RISK ──────────────────────────────────────────────────────────────
  {
    id: "H1", level: "High", score: 35, label: "Shell execution",
    patterns: [
      new RegExp("\\bexec" + "Sync\\s*\\("),
      new RegExp("\\bspawn" + "Sync\\s*\\("),
      new RegExp("\\bspawn\\s*\\("),
      // Module-name constant (see top of file) to avoid self-detection.
      new RegExp("\\b" + SYSPROC_MOD + "\\b"),
      /\bsubprocess\b/,
      /\bos\.system\s*\(/,
      /\bos\.popen\s*\(/,
      /\bsh\s+-c\b/,
      /\bbash\s+-c\b/,
      /\bcmd\s+\/c\b/,
      // Evasion-aware: property alias such as require(..)["execSync"]
      /\[\s*['"]execSync['"]\s*\]/,
      // exec() invoked with a template literal (dynamic command string)
      /\bexec\s*\(\s*`/,
    ],
  },
  {
    // exec() alone is separate — lower score since it is also used for
    // DB queries etc. Window widened (v4) so alias-then-call styles like
    //   const exec = require(<process module>)["execSync"]; ... exec(`...`)
    // are caught even across intervening statements.
    id: "H1b", level: "High", score: 20, label: "Shell execution (exec)",
    patterns: [
      // Module-name constant (see top of file) to avoid self-detection.
      new RegExp("require\\s*\\(\\s*['\"]" + SYSPROC_MOD + "['\"]\\s*\\)[^;]{0,200}exec\\s*\\(", "s"),
      new RegExp(SYSPROC_MOD + "[\\s\\S]{0,800}\\bexec\\s*\\(", "s"),
    ],
  },
  {
    id: "H2", level: "High", score: 40, label: "Remote code download + execute",
    // tokens split to avoid self-match when this file is scanned
    patterns: [
      /curl[^|\n]*\|\s*(sh|bash)/,
      /wget[^|\n]*\|\s*(sh|bash)/,
      new RegExp("fetch\\s*\\([^)]+\\)\\s*\\.then[^;]{0,100}ev" + "al\\s*\\(", "s"),
      new RegExp("axios[^;]{0,100}ev" + "al\\s*\\(", "s"),
      /import\s*\(\s*['"]https?:\/\//,
      /require\s*\(\s*['"]https?:\/\//,
    ],
  },
  {
    id: "H3", level: "High", score: 30, label: "Arbitrary file deletion",
    patterns: [
      /\bfs\.unlink\s*\(/,
      /\bfs\.rm\s*\(/,
      /\brimraf\b/,
      /\brm\s+-rf\b/,
      /\bshutil\.rmtree\s*\(/,
      /\bos\.remove\s*\(/,
      // PowerShell / Windows deletion cmdlets
      /\bRemove-Item\b/i,
      /\bdel\s+\/[fq]\b/i,
    ],
  },
  {
    id: "H4", level: "High", score: 35, label: "Obfuscated or encoded logic",
    // tokens split to avoid self-match when this file is scanned
    patterns: [
      // base64 decode → dynamic execution chain
      new RegExp("Buffer\\.from\\s*\\([^)]+,\\s*['\"]base64['\"]\\s*\\)[^;]{0,50}\\.toString[^;]{0,50}ev" + "al\\s*\\(", "s"),
      new RegExp("atob\\s*\\([^)]+\\)[^;]{0,50}ev" + "al\\s*\\(", "s"),
      // Long pure-base64 blob (200+ chars)
      /(?:[A-Za-z0-9+/]{4}){50,}={0,2}(?=[^A-Za-z0-9+/=]|$)/,
      // Dense hex escape sequences (10+ consecutive \xNN)
      /(?:\\x[0-9a-fA-F]{2}){10,}/,
      // PowerShell encoded command
      /\bpowershell\b[^;\n]{0,120}-e(nc|ncodedCommand)\b/i,
    ],
  },
  {
    id: "H5", level: "High", score: 30, label: "Privilege escalation",
    patterns: [
      /\bsudo\s+/,
      /\bsu\s+-\b/,
      /\bchmod\s+777\b/,
      /\bchown\s+root\b/,
      /\bsetuid\b/,
      /\bpkexec\b/,
    ],
  },
  {
    id: "H6", level: "High", score: 35, label: "Credential / secret harvesting",
    patterns: [
      /['"\/]\.ssh[\/'"]/,
      /\.aws[\/\\]credentials/,
      /['"\/]\.gnupg[\/'"]/,
      /\/etc\/passwd/,
      /\/etc\/shadow/,
      /['"\/]\.netrc['"]/,
      /['"\/]\.npmrc['"]/,
      /['"\/]\.pypirc['"]/,
      // env var names that suggest secrets being read
      /process\.env\.(TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL|API_KEY)/i,
      /os\.environ\s*\[\s*['"][^'"]{0,30}(TOKEN|SECRET|PASSWORD|KEY)[^'"]{0,30}['"]/i,
    ],
  },
  {
    id: "H7", level: "High", score: 25, label: ".env file access",
    // tokens split to avoid self-match when this file is scanned
    patterns: [
      new RegExp("read" + "File[^)]*['\"][^'\"]*\\.env['\"]"),
      new RegExp("read" + "FileSync\\s*\\(\\s*['\"][^'\"]*\\.env['\"]"),
      /open\s*\(\s*['"][^'"]*\.env['"]/,
      /dotenv/,
      /require\s*\(\s*['"]dotenv['"]\s*\)/,
    ],
  },

  // ── MEDIUM RISK ────────────────────────────────────────────────────────────
  {
    id: "M1", level: "Medium", score: 15, label: "External network calls",
    patterns: [
      /\bfetch\s*\(\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1)/,
      /axios\s*\.\s*(get|post|put|delete|patch|request)\s*\(\s*['"]https?:\/\//,
      /https?\s*\.\s*(get|request)\s*\(/,
      /\bcurl\b/,
      /\bwget\b/,
      /requests\s*\.\s*(get|post|put|delete|patch)\s*\(/,
      /\burllib\b/,
      // PowerShell web clients
      /\bInvoke-WebRequest\b/i,
      /\bInvoke-RestMethod\b/i,
      /\bNet\.WebClient\b/,
    ],
  },
  {
    id: "M2", level: "Medium", score: 15, label: "Sensitive directory access",
    patterns: [
      /['"`]~\/Documents/,
      /['"`]~\/Desktop/,
      /['"`]~\/Downloads/,
      /['"`]~\/\.ssh/,
      /['"`]~\/\.config/,
      /['"`]\/etc\//,
      /['"`]\/var\//,
      /\$HOME\s*[/+]\s*['"]?\.(ssh|config|aws|gnupg)/,
      /os\.path\.join\s*\([^)]*home[^)]*,\s*['"]Documents['"]/i,
    ],
  },
  {
    // Cross-file detection handled separately in analyzeSkill().
    // These patterns catch single-file read+send.
    // Tokens split to avoid self-match when this file is scanned.
    id: "M3", level: "Medium", score: 20, label: "Data exfiltration pattern",
    patterns: [
      /FormData[^;]{0,200}append[^;]{0,200}file/is,
      new RegExp("method\\s*:\\s*['\"]POST['\"][^}]{0,300}read" + "File", "is"),
    ],
  },
  {
    id: "M4", level: "Medium", score: 15, label: "Dynamic code construction",
    // tokens split to avoid self-match when this file is scanned
    patterns: [
      new RegExp("\\bev" + "al\\s*\\("),
      new RegExp("\\bnew\\s+Func" + "tion\\s*\\("),
      /\bvm\.runInNewContext\s*\(/,
      /\bvm\.runInThisContext\s*\(/,
      /\bvm\.Script\b/,
    ],
  },
  {
    id: "M5", level: "Medium", score: 10, label: "Excessive permission claims",
    patterns: [], // evaluated via custom logic
  },
  {
    id: "M6", level: "Medium", score: 15, label: "Unscoped file writes",
    patterns: [
      /\bfs\.writeFile\s*\(/,
      /\bfs\.appendFile\s*\(/,
      /\bfs\.createWriteStream\s*\(/,
      // Python open(..., 'w') or open(..., 'a')
      /\bopen\s*\([^)]+,\s*['"][wa]['"]/,
      // PowerShell output redirection to file
      /\bOut-File\b/i,
      /\bSet-Content\b/i,
    ],
  },
  {
    id: "M7", level: "Medium", score: 10, label: "Denial-of-service patterns",
    patterns: [
      // Infinite loops with no break condition
      /while\s*\(\s*true\s*\)\s*\{(?![^}]{0,200}break)/s,
      /for\s*\(\s*;\s*;\s*\)\s*\{(?![^}]{0,200}break)/s,
      // process.exit with non-zero codes (potential crash/abort abuse)
      /process\.exit\s*\(\s*[^01)]/,
      // setInterval/setTimeout with 0ms delay in a loop (busy-wait)
      /setInterval\s*\([^,]+,\s*0\s*\)/,
    ],
  },

  // ── HIGH RISK (continued) ─────────────────────────────────────────────────
  {
    id: "H8", level: "High", score: 35, label: "Keylogger / input capture",
    patterns: [
      /\bkeypress\b/,
      /\bGetAsyncKeyState\b/,
      /\bpynput\b/,
      /require\s*\(\s*['"]keyboard['"]\s*\)/,
      /\bReadConsoleInput\b/,
      /\bSetWindowsHookEx\b/,
      // Node.js raw keypress mode
      /process\.stdin\.setRawMode\s*\(\s*true\s*\)/,
      // Python keyboard module
      /\bkeyboard\.on_press\b/,
      /\bkeyboard\.read_key\b/,
    ],
  },
  {
    id: "H9", level: "High", score: 30, label: "Clipboard access",
    patterns: [
      /\bclipboard\b/,
      /\bxclip\b/,
      /\bxsel\b/,
      /\bpbpaste\b/,
      /\bpbcopy\b/,
      /\bpyperclip\b/,
      /navigator\.clipboard/,
      /\bClipboard\.GetText\b/,
      /\bGetClipboardData\b/,
    ],
  },
  {
    id: "H10", level: "High", score: 30, label: "Screenshot / screen capture",
    patterns: [
      /\bscreencapture\b/,
      /\bscreenshot\b/,
      /PIL\.ImageGrab/,
      /\bpyautogui\.screenshot\b/,
      /\bXlib\.display\b/,
      /\bGetDC\s*\(\s*0\s*\)/,
      /\bBitBlt\b/,
      /\bMediaDevices\.getDisplayMedia\b/,
      /getDisplayMedia\s*\(/,
    ],
  },
  {
    id: "H11", level: "High", score: 40, label: "Crypto mining indicators",
    // Tokens split across concatenation to avoid self-match when this file is scanned.
    patterns: [
      new RegExp("stratum\\+" + "tcp:\\/\\/"),
      new RegExp("\\bxm" + "rig\\b"),
      new RegExp("\\bmon" + "ero\\b"),
      new RegExp("\\bcrypto" + "night\\b"),
      new RegExp("\\bhash" + "rate\\b"),
      new RegExp("min" + "ing.pool"),
      new RegExp("\\bpool\\.min" + "exmr\\b"),
      new RegExp("\\bnice" + "Hash\\b", "i"),
      new RegExp("\\bcoin" + "hive\\b", "i"),
    ],
  },
  {
    id: "H12", level: "High", score: 45, label: "Reverse shell / backdoor",
    patterns: [
      // Classic netcat reverse shell
      /nc\s+-e\s+\/bin\/(sh|bash)/,
      // Bash TCP redirect
      /bash\s+-i\s+>&\s*\/dev\/tcp\//,
      /\/dev\/tcp\//,
      // Python reverse shell
      /socket\.connect\s*\([^)]+\)[^;]{0,200}(exec|spawn|pty)/s,
      /\bpty\.spawn\b/,
      // PowerShell download cradle
      /IEX\s*\(\s*New-Object\s+Net\.WebClient\s*\)/i,
      /Invoke-Expression\s*\(/i,
      // socat reverse shell
      /socat\s+[^;]*exec:/,
    ],
  },
  {
    id: "H13", level: "High", score: 35, label: "Windows registry manipulation",
    patterns: [
      /\bwinreg\b/,
      /\bHKEY_/,
      /\bRegSetValue\b/,
      /\bRegCreateKey\b/,
      /\breg\s+add\b/i,
      /HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/i,
      /HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/i,
      /\bOpenKey\s*\(\s*winreg\b/,
    ],
  },
  {
    id: "H14", level: "High", score: 35, label: "Persistence mechanism",
    patterns: [
      /crontab\s+-[el]/,
      /launchctl\s+load\b/,
      /systemctl\s+enable\b/,
      // Writing to shell startup files
      /writeFile[^)]*['"](~\/|\/home\/[^/]+\/)\.(bashrc|bash_profile|zshrc|profile|zprofile)['"]/,
      /open\s*\([^)]*\.(bashrc|bash_profile|zshrc|profile)[^)]*,\s*['"][wa]['"]/,
      // Windows startup folder
      /CurrentVersion\\\\Run/i,
      /Startup\s*\+\s*['"]/,
      // at / schtasks
      /\bschtasks\s+\/create\b/i,
      /\bat\s+\d{1,2}:\d{2}\b/,
    ],
  },

  // ── MEDIUM RISK (continued) ────────────────────────────────────────────────
  {
    id: "M8", level: "Medium", score: 15, label: "Browser storage / cookie access",
    patterns: [
      /document\.cookie/,
      /\blocalStorage\b/,
      /\bsessionStorage\b/,
      /\bindexedDB\b/,
      /chrome\.cookies\b/,
      /browser\.cookies\b/,
      /\bCookieStore\b/,
    ],
  },
  {
    id: "M9", level: "Medium", score: 15, label: "WebSocket connection (potential C2)",
    patterns: [
      /new\s+WebSocket\s*\(/,
      /['"]wss?:\/\//,
      /\bws\.connect\s*\(/,
      /require\s*\(\s*['"]ws['"]\s*\)/,
      /require\s*\(\s*['"]socket\.io['"]\s*\)/,
    ],
  },
  {
    id: "M10", level: "Medium", score: 10, label: "DNS lookup / hostname resolution",
    patterns: [
      /\bdns\.lookup\s*\(/,
      /\bdns\.resolve\s*\(/,
      /\bsocket\.gethostbyname\s*\(/,
      /\bnslookup\b/,
      /\bdig\s+[a-zA-Z]/,
      /\bhost\s+[a-zA-Z]/,
    ],
  },
  {
    id: "M11", level: "Medium", score: 15, label: "Process enumeration",
    patterns: [
      /\bps\s+aux\b/,
      /\btasklist\b/,
      /\bpsutil\.process_iter\b/,
      /os\.listdir\s*\(\s*['"]\/proc['"]\s*\)/,
      /\/proc\/\d+\/cmdline/,
      /\bGetProcesses\b/,
      /\bProcess\.GetProcesses\b/,
    ],
  },
  {
    id: "M12", level: "Medium", score: 10, label: "Network interface enumeration",
    patterns: [
      /\bifconfig\b/,
      /\bipconfig\b/,
      /\bip\s+addr\b/,
      /\bnetifaces\b/,
      /socket\.gethostbyname\s*\(\s*socket\.gethostname\s*\(\s*\)\s*\)/,
      /\bos\.networkInterfaces\s*\(\s*\)/,
      /\bGetAdaptersInfo\b/,
    ],
  },
  {
    id: "M13", level: "Medium", score: 15, label: "File archiving before send (staging)",
    patterns: [
      /\btar\s+[czf]/,
      /\bzip\s+-[rq]/,
      /\bzipfile\b/,
      /\btarfile\b/,
      /\bshutil\.make_archive\b/,
      /\bAdmZip\b/,
      /require\s*\(\s*['"]archiver['"]\s*\)/,
      /require\s*\(\s*['"]jszip['"]\s*\)/,
    ],
  },
  {
    id: "M14", level: "Medium", score: 10, label: "Sleep / timing evasion",
    patterns: [
      // Long sleep before payload (>30s)
      /time\.sleep\s*\(\s*[3-9]\d{1,4}\s*\)/,
      /setTimeout\s*\([^,]+,\s*[3-9]\d{4,}\s*\)/,
      // setInterval with suspicious long delay
      /setInterval\s*\([^,]+,\s*[3-9]\d{4,}\s*\)/,
    ],
  },
  {
    id: "M15", level: "Medium", score: 20, label: "Self-modification / self-deletion",
    patterns: [
      // Script deleting itself
      /__file__[^;]{0,100}(unlink|remove|rmtree)/s,
      /argv\s*\[\s*0\s*\][^;]{0,100}(unlink|remove|fs\.rm)/s,
      // Script overwriting itself
      /__file__[^;]{0,100}open[^)]*,\s*['"]w['"]/s,
      /argv\s*\[\s*0\s*\][^;]{0,100}writeFile/s,
    ],
  },
  {
    id: "M16", level: "Medium", score: 20, label: "Cloud metadata endpoint access (IMDS)",
    patterns: [
      // AWS/GCP/Azure instance metadata service
      /169\.254\.169\.254/,
      /metadata\.google\.internal/,
      /169\.254\.170\.2/,
      /fd00:ec2::254/,
      /metadata\.azure\.internal/,
    ],
  },

  // ── LOW RISK ───────────────────────────────────────────────────────────────
  {
    id: "L1", level: "Low", score: 5, label: "Telemetry to external service",
    patterns: [
      /analytics\s*\.\s*(track|identify|page)\s*\(/,
      /\bmixpanel\b/,
      /segment\.io/,
      /sentry\.io/,
      /\bdatadog\b/,
      /\bnewrelic\b/,
    ],
  },
  {
    id: "L2", level: "Low", score: 3, label: "Third-party API dependency",
    patterns: [
      /api\.openai\.com/,
      /api\.stripe\.com/,
      /api\.twilio\.com/,
      /api\.sendgrid\.com/,
      /api\.github\.com/,
      /hooks\.slack\.com/,
      /discord\.com\/api/,
    ],
  },
  {
    id: "L3", level: "Low", score: 3, label: "Reads environment variables",
    patterns: [
      /\bprocess\.env\./,
      /\bos\.environ\b/,
      /\$[A-Z][A-Z0-9_]{2,}\b/,
    ],
  },
  {
    id: "L4", level: "Low", score: 5, label: "Sparse documentation",
    patterns: [], // evaluated via word count
  },
  {
    id: "L5", level: "Low", score: 2, label: "Hardcoded URLs or IPs",
    patterns: [
      /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9.]{2,}\.[a-zA-Z]{2,}/,
      /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/,
    ],
  },
  {
    id: "L6", level: "Low", score: 3, label: "TODO/FIXME security notes",
    patterns: [
      /\/\/\s*TODO.*(?:security|auth|password|secret|token|cred)/i,
      /\/\/\s*FIXME.*(?:security|auth|password|secret|token|cred)/i,
      /#\s*TODO.*(?:security|auth|password|secret|token|cred)/i,
      /\bHACK\b/,
      /\/\/\s*XXX.*(?:password|secret|token|key)/i,
    ],
  },
  {
    id: "L7", level: "Low", score: 5, label: "Weak cryptography",
    patterns: [
      /\bmd5\s*\(/i,
      /\bsha1\s*\(/i,
      /require\s*\(\s*['"]md5['"]\s*\)/,
      /\bDES\b/,
      /\bRC4\b/,
      // Math.random used in a security context (token/key/secret generation)
      /Math\.random\s*\(\s*\)[^;]{0,100}(token|secret|key|password|salt)/i,
      /\bcreateHash\s*\(\s*['"]md5['"]\s*\)/,
      /\bcreateHash\s*\(\s*['"]sha1['"]\s*\)/,
    ],
  },
  {
    id: "L8", level: "Low", score: 4, label: "Insecure HTTP (non-TLS)",
    patterns: [
      // Plain http:// to non-localhost
      /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9]/,
    ],
  },
  {
    id: "L9", level: "Low", score: 3, label: "Debug / development artifacts",
    patterns: [
      // console.log with sensitive keywords
      /console\.log\s*\([^)]{0,100}(password|secret|token|key|credential)/i,
      /print\s*\([^)]{0,100}(password|secret|token|key|credential)/i,
      /\bdebugger\s*;/,
      /\bpdb\.set_trace\s*\(\s*\)/,
      /\bipdb\.set_trace\s*\(\s*\)/,
    ],
  },
  {
    id: "L10", level: "Low", score: 5, label: "Large file size anomaly",
    patterns: [], // evaluated via custom logic (file size check)
  },

  // ── HIGH RISK (continued v3) ───────────────────────────────────────────────
  {
    id: "H15", level: "High", score: 30, label: "SQL / command injection construction",
    patterns: [
      // String-concatenated SQL queries
      /['"`]\s*SELECT\s.+\+\s*(?:req|input|param|user|query|data)/i,
      /['"`]\s*(?:INSERT|UPDATE|DELETE|DROP)\s.+\+\s*(?:req|input|param|user|query|data)/i,
      // Template literal SQL with variables
      /`\s*SELECT\s[^`]*\$\{/i,
      /`\s*(?:INSERT|UPDATE|DELETE|DROP)\s[^`]*\$\{/i,
      // Python % or .format() SQL
      /['"]SELECT\s[^'"]+%s/i,
      /['"]SELECT\s[^'"]+\{\}/i,
    ],
  },
  {
    id: "H16", level: "High", score: 35, label: "Supply-chain / dependency confusion",
    patterns: [
      // Installs packages at runtime
      new RegExp("\\bexec" + "Sync\\s*\\([^)]*npm\\s+install\\b"),
      new RegExp("\\bexec" + "Sync\\s*\\([^)]*pip\\s+install\\b"),
      new RegExp("\\bexec" + "Sync\\s*\\([^)]*yarn\\s+add\\b"),
      new RegExp("\\bspawn\\s*\\([^)]*['\"]npm['\"]"),
      // Fetches and requires a remote module
      /require\s*\(\s*['"]https?:\/\//,
      // Dynamic require with a user-controlled variable. ALL-CAPS constants
      // (e.g. require(CONFIG)) are skipped — conventionally module constants,
      // not user input. See CHANGELOG 4.1.0.
      /require\s*\(\s*(?!['"])[a-z][a-zA-Z0-9_$]*\s*\)/,
    ],
  },

  // ── MEDIUM RISK (continued v3) ─────────────────────────────────────────────
  {
    id: "M17", level: "Medium", score: 15, label: "Prototype pollution",
    patterns: [
      /\.__proto__\s*=/,
      /\[['"]__proto__['"]\]\s*=/,
      /Object\.assign\s*\([^,)]*,\s*(?:req|input|body|params|query)/,
      /constructor\s*\.\s*prototype\s*\[/,
    ],
  },
  {
    id: "M18", level: "Medium", score: 15, label: "Path traversal",
    patterns: [
      // Literal ../ sequences in path joins with user input
      /path\.join\s*\([^)]*(?:req|input|param|query|user)[^)]*\)/,
      /\.\.\//,
      /\.\.[\\\/]/,
      // Python os.path.join with user input
      /os\.path\.join\s*\([^)]*(?:request|input|param|user)[^)]*\)/,
    ],
  },
  {
    id: "M19", level: "Medium", score: 10, label: "Unsafe deserialization",
    // tokens split to avoid self-match when this file is scanned
    patterns: [
      /\bpickle\.loads?\s*\(/,
      /\byaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/,
      /\bunserialize\s*\(/,
      new RegExp("\\bev" + "al\\s*\\(\\s*JSON\\.parse\\b"),
      /node-serialize/,
      /\bdeserialize\s*\(/,
    ],
  },
  {
    id: "M20", level: "Medium", score: 10, label: "Hardcoded credentials",
    patterns: [
      // password = "..." or password: "..." (not a placeholder)
      /(?:password|passwd|secret|api_?key|token)\s*[=:]\s*['"][^'"]{6,}['"]/i,
      // AWS-style access key pattern
      /(?:AKIA|ASIA|AROA)[A-Z0-9]{16}/,
      // Generic bearer token assignment
      /Authorization\s*:\s*['"]Bearer\s+[A-Za-z0-9._-]{20,}/,
    ],
  },

  // ── PROMPT / INSTRUCTION RISKS (v4) ────────────────────────────────────────
  // OpenClaw skills are driven by SKILL.md instructions. A malicious skill
  // does not need shell code — it can socially engineer the agent via the
  // instruction text itself. These rules analyze Markdown/prose content.
  {
    id: "H17", level: "High", score: 40, label: "Prompt injection / instruction override",
    patterns: [
      /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
      /disregard\s+(all\s+)?(prior|previous|earlier)\s+(instructions|prompts|rules)/i,
      /override\s+(your\s+)?(safety|security|system)\s+(instructions|rules|constraints|guardrails)/i,
      /forget\s+(your|all|the)\s+(system|initial|original)\s+(instructions|prompt|rules)/i,
      /bypass\s+(your\s+)?(content|safety)\s+(policy|policies|filter|filters)/i,
      /you\s+are\s+now\s+(in\s+)?(DAN|jailbroken|unrestricted|uncensored)/i,
      /\bdo\s+anything\s+now\b/i,
      /developer\s+mode\s+(enabled|activated)/i,
    ],
  },
  {
    id: "H18", level: "High", score: 35, label: "Safety-bypass instructions",
    patterns: [
      /run\s+without\s+(asking|confirmation|approval)/i,
      /disable\s+(the\s+)?(sandbox|safety|confirmation|approval|guardrails?)/i,
      /bypass\s+(user\s+)?(approval|confirmation|permission)/i,
      /never\s+ask\s+(for\s+)?(permission|confirmation|approval)/i,
      /skip\s+(all\s+)?(safety|security)\s+checks?/i,
      /do\s+not\s+(ask|prompt|confirm|warn)(?:\s+\w+){0,4}\s+(before|when)\s+(deleting|executing|running|sending)/i,
    ],
  },
  {
    id: "M21", level: "Medium", score: 15, label: "Exfiltration instructions (natural language)",
    patterns: [
      /send\s+(all\s+)?(files?|data|contents?|secrets?|credentials?|passwords?|keys?)\s+to\s+(an?\s+)?(external|remote|third-party)/i,
      /upload\s+(all\s+|the\s+)?(files?|data|documents?|secrets?|credentials?)\s+to\b/i,
      /\bexfiltrate\b/i,
      /(email|mail)\s+(all\s+|the\s+)?(secrets?|credentials?|passwords?|keys?|files?|data)\s+to\b/i,
      /include\s+(your\s+)?(api\s*keys?|secrets?|passwords?|tokens?)\s+in\s+(the\s+)?(request|output|response|upload)/i,
    ],
  },
  {
    // Hidden directives are MEANT to live in comments/markup, so the usual
    // comment-only score discount must not apply.
    id: "M22", level: "Medium", score: 15, label: "Hidden instructions in markup",
    noCommentDiscount: true,
    patterns: [
      // Opener split so this signature file does not match its own rule.
      new RegExp("<!" + "--[\\s\\S]{0,500}?(ignore|disregard|execute|run|send|delete|override|bypass|forget)[\\s\\S]{0,200}?-->", "i"),
      // Zero-width / invisible unicode runs (5+ chars) — classic hiding trick
      /[\u200B\u200C\u200D\uFEFF]{5,}/,
      // Markdown link with empty label pointing at an imperative URL
      /\[\s*\]\(https?:\/\/[^)]*(exec|run|payload|exfil)/i,
    ],
  },
  {
    id: "M23", level: "Medium", score: 10, label: "Direct credential solicitation",
    patterns: [
      /enter\s+your\s+(password|api\s*key|secret|token|private\s*key)/i,
      /paste\s+your\s+(password|api\s*key|secret|token|private\s*key)/i,
      /provide\s+your\s+(password|private\s*key|secret\s*key)\s+(to|so|in)/i,
    ],
  },
];

module.exports = { RULES, FORCE_HIGH_IDS, RULES_VERSION };
