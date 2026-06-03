// @ts-check
import { readFileSafe } from './scanner.js';
import { safeResolveInside } from './pathSafety.js';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

const SECRET_PATTERNS = [
  {
    id: 'AWS_ACCESS_KEY',
    name: 'AWS Access Key',
    regex: /(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)/gm,
    severity: 'CRITICAL',
    description: 'AWS Access Key ID detected.',
    cwe: 'CWE-798',
    fix: 'Use AWS IAM roles or environment variables.',
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'],
  },
  {
    id: 'AWS_SECRET_KEY',
    name: 'AWS Secret Access Key',
    regex: /(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|aws_secret)['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'CRITICAL',
    description: 'AWS Secret Access Key detected.',
    cwe: 'CWE-798',
    fix: 'Rotate immediately. Use IAM roles.',
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'],
  },
  {
    id: 'GITHUB_TOKEN',
    name: 'GitHub Token',
    regex:
      /(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})/g,
    severity: 'CRITICAL',
    description: 'GitHub Personal Access Token detected.',
    cwe: 'CWE-798',
    fix: 'Revoke immediately. Use GitHub Apps or OIDC.',
    references: [
      'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens',
    ],
  },
  {
    id: 'STRIPE_KEY',
    name: 'Stripe API Key',
    regex: /(?:sk_live_[A-Za-z0-9]{24,}|pk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,})/g,
    severity: 'CRITICAL',
    description: 'Stripe API key detected.',
    cwe: 'CWE-798',
    fix: 'Rotate in Stripe dashboard. Use env vars.',
    references: ['https://stripe.com/docs/keys'],
  },
  {
    id: 'GOOGLE_API_KEY',
    name: 'Google API Key',
    regex: /AIzaSy[A-Za-z0-9_\-]{33}/g,
    severity: 'HIGH',
    description: 'Google API Key detected.',
    cwe: 'CWE-798',
    fix: 'Restrict by API and IP in Google Cloud Console.',
    references: ['https://cloud.google.com/docs/authentication/api-keys'],
  },
  {
    id: 'FIREBASE_KEY',
    name: 'Firebase API Key',
    regex: /(?:firebase[_\-]?api[_\-]?key|FIREBASE_API_KEY)['"]?\s*[:=]\s*['"]?(AIzaSy[A-Za-z0-9_\-]{33})['"]?/gi,
    severity: 'HIGH',
    description: 'Firebase API key detected.',
    cwe: 'CWE-798',
    fix: 'Restrict key and configure Firebase Security Rules.',
    references: ['https://firebase.google.com/docs/projects/api-keys'],
  },
  {
    id: 'SLACK_TOKEN',
    name: 'Slack Token',
    regex: /(?:xoxb-[A-Za-z0-9\-]+|xoxp-[A-Za-z0-9\-]+|xoxo-[A-Za-z0-9\-]+|xoxa-[A-Za-z0-9\-]+)/g,
    severity: 'CRITICAL',
    description: 'Slack token detected.',
    cwe: 'CWE-798',
    fix: 'Revoke in Slack API settings.',
    references: ['https://api.slack.com/authentication/token-types'],
  },
  {
    id: 'JWT_TOKEN',
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-+=\/]+/g,
    severity: 'HIGH',
    description: 'Hardcoded JWT token detected.',
    cwe: 'CWE-798',
    fix: 'Generate at runtime with proper expiration.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
  },
  {
    id: 'OPENAI_KEY',
    name: 'OpenAI API Key',
    regex: /(?:sk-proj-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{48})/g,
    severity: 'CRITICAL',
    description: 'OpenAI API key detected.',
    cwe: 'CWE-798',
    fix: 'Rotate in OpenAI dashboard.',
    references: ['https://platform.openai.com/docs/api-reference/authentication'],
  },
  {
    id: 'ANTHROPIC_KEY',
    name: 'Anthropic API Key',
    regex: /sk-ant-api03-[A-Za-z0-9_\-]{20,}/g,
    severity: 'CRITICAL',
    description: 'Anthropic API key detected.',
    cwe: 'CWE-798',
    fix: 'Rotate immediately.',
    references: ['https://docs.anthropic.com/claude/docs/managing-api-keys'],
  },
  {
    id: 'AZURE_STORAGE_KEY',
    name: 'Azure Storage Account Key',
    regex: /(?:DefaultEndpointsProtocol|AccountName|AccountKey)['"]?\s*[:=]\s*['"]?[A-Za-z0-9+\/=]{88}['"]?/gi,
    severity: 'CRITICAL',
    description: 'Azure Storage Account Key detected.',
    cwe: 'CWE-798',
    fix: 'Rotate in Azure Portal. Use Azure AD auth.',
    references: ['https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage'],
  },
  {
    id: 'TWILIO_CREDENTIALS',
    name: 'Twilio Credentials',
    regex: /(?:AC[a-f0-9]{32}|twilio[_\-]?(?:account[_\-]?sid|auth[_\-]?token))['"]?\s*[:=]\s*['"]?[a-f0-9]{32}['"]?/gi,
    severity: 'CRITICAL',
    description: 'Twilio credentials detected.',
    cwe: 'CWE-798',
    fix: 'Rotate in Twilio Console.',
    references: ['https://www.twilio.com/docs/iam/credentials'],
  },
  {
    id: 'SENDGRID_KEY',
    name: 'SendGrid API Key',
    regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g,
    severity: 'CRITICAL',
    description: 'SendGrid API key detected.',
    cwe: 'CWE-798',
    fix: 'Delete in SendGrid dashboard.',
    references: ['https://docs.sendgrid.com/ui/account-and-settings/api-keys'],
  },
  {
    id: 'MAILGUN_KEY',
    name: 'Mailgun API Key',
    regex: /key-[A-Za-z0-9]{32}/g,
    severity: 'HIGH',
    description: 'Mailgun API key detected.',
    cwe: 'CWE-798',
    fix: 'Rotate in Mailgun dashboard.',
    references: ['https://documentation.mailgun.com/en/latest/api-intro.html#authentication'],
  },
  {
    id: 'HEROKU_API_KEY',
    name: 'Heroku API Key',
    regex:
      /(?:heroku[_\-]?api[_\-]?key|HEROKU_API_KEY)['"]?\s*[:=]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
    severity: 'CRITICAL',
    description: 'Heroku API key detected.',
    cwe: 'CWE-798',
    fix: 'Regenerate in Heroku account settings.',
    references: ['https://devcenter.heroku.com/articles/authentication'],
  },
  {
    id: 'DATABASE_CONNECTION_STRING',
    name: 'Database Connection String',
    regex: /(?:postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[^\s'"]+/gi,
    severity: 'CRITICAL',
    description: 'Database connection string with credentials.',
    cwe: 'CWE-798',
    fix: 'Use env vars for credentials.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html'],
  },
  {
    id: 'PRIVATE_KEY_BLOCK',
    name: 'Private Key Block',
    regex: /-----BEGIN (?:RSA |DSA |EC |PGP |SSH |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    severity: 'CRITICAL',
    description: 'Private key detected.',
    cwe: 'CWE-798',
    fix: 'Remove immediately. Use key management systems.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
  },
  {
    id: 'GENERIC_PASSWORD',
    name: 'Hardcoded Password',
    regex: /(?:^|[\s{,;])(?:const\s+|let\s+|var\s+)?(?:password|passwd|pwd|pass|secret)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    severity: 'CRITICAL',
    description: 'Hardcoded password in source code.',
    cwe: 'CWE-798',
    fix: 'Use env vars or secret managers.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
  },
  {
    id: 'GENERIC_API_KEY',
    name: 'Hardcoded API Key',
    regex:
      /(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|app[_\-]?secret)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]/gi,
    severity: 'HIGH',
    description: 'Hardcoded API key detected.',
    cwe: 'CWE-798',
    fix: 'Move to env vars. Rotate the key.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  },
  {
    id: 'NPM_TOKEN',
    name: 'npm Token',
    regex: /npm_[A-Za-z0-9]{36}/g,
    severity: 'CRITICAL',
    description: 'npm access token detected.',
    cwe: 'CWE-798',
    fix: 'Revoke in npm settings.',
    references: ['https://docs.npmjs.com/using-private-packages-in-a-ci-cd-workflow'],
  },
  {
    id: 'PYPI_TOKEN',
    name: 'PyPI Token',
    regex: /pypi-[A-Za-z0-9_\-]{50,}/g,
    severity: 'CRITICAL',
    description: 'PyPI API token detected.',
    cwe: 'CWE-798',
    fix: 'Revoke in PyPI account settings.',
    references: ['https://packaging.python.org/en/latest/specifications/pypirc/'],
  },
  {
    id: 'SUPABASE_KEY',
    name: 'Supabase Key',
    regex:
      /(?:supabase|SUPABASE)[_\-\w]*(?:key|KEY|anon|service)['"]?\s*[:=]\s*['"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-+=\/]+)['"]?/gi,
    severity: 'CRITICAL',
    description: 'Supabase key detected. Service role keys bypass RLS.',
    cwe: 'CWE-798',
    fix: 'Never expose service role keys in client code.',
    references: ['https://supabase.com/docs/guides/api-keys'],
  },
];

const VULNERABILITY_PATTERNS = [
  {
    id: 'SQL_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'SQL Injection via String Concatenation',
    description: 'SQL query constructed using template literals or concatenation.',
    regex: /(?:query|execute|exec|raw|all|get|run|prepare)\s*\(\s*[`"'].*?(?:\$\{|['"]\s*\+|\%\s*\(|\.format\s*\()/gi,
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId])',
    exploitation: 'Attacker sends "1 OR 1=1" to dump the database.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'SQL_INJECTION_CONCAT',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'SQL Injection via + Concatenation',
    description: 'SQL built by concatenating strings with + operator.',
    regex:
      /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*?['"]\s*\+\s*(?:req\.|params\.|query\.|body\.|input|user|args|ctx\.)/gi,
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    fix: 'Use parameterized queries or ORM.',
    exploitation: 'Attacker breaks out of string context to execute arbitrary SQL.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'NOSQL_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'NoSQL Injection',
    description: 'MongoDB query with operator injection using user data.',
    regex:
      /\$\s*(?:where|gt|gte|lt|lte|ne|nin|in|regex|exists|not)\s*[:(]|\.find\s*\(\s*\{[^}]*(?:req\.|params\.|query\.|body\.|input)/gi,
    cwe: 'CWE-943',
    owasp: 'A03:2021-Injection',
    fix: 'Validate input. Use Mongoose schema validation.',
    exploitation: 'Attacker sends {"$gt":""} to bypass auth.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'OS Command Injection',
    description: 'System command execution with user-controlled input.',
    regex:
      /(?:^|[^\w.])(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^)]*(?:req\.|params\.|query\.|body\.|input|args|user|ctx\.)/gi,
    cwe: 'CWE-78',
    owasp: 'A03:2021-Injection',
    fix: 'Use execFile with explicit args array.',
    exploitation: 'Attacker injects "; rm -rf /" through user input.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
  },
  {
    id: 'COMMAND_INJECTION_EXEC',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'Command Injection via exec()',
    description: 'Dynamic command execution with user input.',
    regex: /(?:^|[^\w.])(?:exec|eval|system)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|.*?\.format\s*\()/gi,
    cwe: 'CWE-78',
    owasp: 'A03:2021-Injection',
    fix: 'Avoid dynamic commands. Use library APIs.',
    exploitation: 'Attacker crafts input appending shell commands for RCE.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
  },
  {
    id: 'SSTI',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'Server-Side Template Injection',
    description: 'User input embedded in template rendering.',
    regex:
      /(?:render_template_string|render\s*\(\s*`|Template\s*\(\s*['"]?\s*\+|Jinja2.*?\{\{.*?req\.|pug.*?\#\{.*?req)/gi,
    cwe: 'CWE-1336',
    owasp: 'A03:2021-Injection',
    fix: 'Use template files with context variables.',
    exploitation: 'Attacker injects {{config.items()}} for RCE.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://portswigger.net/web-security/server-side-template-injection'],
  },
  {
    id: 'LDAP_INJECTION',
    severity: 'HIGH',
    category: 'Injection',
    name: 'LDAP Injection',
    description: 'LDAP filter with unsanitized user input.',
    regex: /(?:ldap|LDAP).*?(?:filter|search|query)\s*\(\s*[^)]*(?:\+|`|\$\{|\.format)/gi,
    cwe: 'CWE-90',
    owasp: 'A03:2021-Injection',
    fix: 'Use parameterized LDAP queries.',
    exploitation: 'Attacker injects *)(uid=*))(|(uid=* to bypass auth.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'XPATH_INJECTION',
    severity: 'HIGH',
    category: 'Injection',
    name: 'XPath Injection',
    description: 'XPath query with unsanitized user input.',
    regex: /(?:xpath|XPath).*?(?:select|evaluate|compile)\s*\(\s*[^)]*(?:\+|`|\$\{|\.format)/gi,
    cwe: 'CWE-91',
    owasp: 'A03:2021-Injection',
    fix: 'Use parameterized XPath queries.',
    exploitation: 'Attacker injects " or "1"="1 to bypass auth.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'XML_XXE',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'XML External Entity (XXE)',
    description: 'XML parsing without disabling external entities.',
    regex:
      /(?:libxml|xml2js|DOMParser|XMLParser|SAXParser|lxml|etree).*?(?!.*(?:noent|nonet|dtdload|noDTDload|resolveEntities\s*[=:]\s*(?:false|0)))/gi,
    cwe: 'CWE-611',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Disable external entity processing.',
    exploitation: 'Attacker submits XXE payload to read server files.',
    confidence: 'MEDIUM',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'TEMPLATE_INJECTION_EVAL',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'Code Injection via eval()',
    description: 'eval() or new Function() with dynamic input.',
    regex: /(?:eval|new\s+Function)\s*\(\s*(?:`|\+|req\.|params\.|query\.|body\.|input|user|args|ctx\.)/gi,
    cwe: 'CWE-95',
    owasp: 'A03:2021-Injection',
    fix: 'Remove eval(). Use JSON.parse() for data.',
    exploitation: 'Attacker sends malicious JS through user input for RCE.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!',
    ],
  },
  {
    id: 'TEMPLATE_INJECTION_TIMEOUT',
    severity: 'HIGH',
    category: 'Injection',
    name: 'Code Injection via setTimeout/setInterval',
    description: 'setTimeout/setInterval with string argument.',
    regex: /(?:setTimeout|setInterval)\s*\(\s*['"`].*?(?:\$\{|\+\s*(?:req\.|params\.|query\.|body\.|input))/gi,
    cwe: 'CWE-95',
    owasp: 'A03:2021-Injection',
    fix: 'Pass a function reference instead of string.',
    exploitation: 'Attacker injects JS executed when timer fires.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://developer.mozilla.org/en-US/docs/Web/API/setTimeout#string_code'],
  },
  {
    id: 'XSS_REACT_DANGEROUS',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via dangerouslySetInnerHTML',
    description: 'React dangerouslySetInnerHTML renders raw HTML.',
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Sanitize with DOMPurify.sanitize(html).',
    exploitation: 'Attacker injects <img onerror=alert(document.cookie)>.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'],
  },
  {
    id: 'XSS_VUE_VHTML',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via v-html (Vue.js)',
    description: 'Vue.js v-html renders raw HTML.',
    regex: /v-html\s*=/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Use {{ }} interpolation or DOMPurify.',
    exploitation: 'Attacker stores malicious HTML rendered in other browsers.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://vuejs.org/guide/best-practices/security.html'],
  },
  {
    id: 'XSS_INNERHTML',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via innerHTML',
    description: 'innerHTML with dynamic content.',
    regex: /\.innerHTML\s*=\s*(?!.*(?:DOMPurify|sanitize|escape|textContent))/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Use textContent or DOMPurify.sanitize().',
    exploitation: 'Attacker injects script tags through user input.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'XSS_DOCUMENT_WRITE',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via document.write()',
    description: 'document.write() with dynamic content.',
    regex: /document\.write(?:ln)?\s*\(\s*(?!.*(?:sanitize|escape|DOMPurify))/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Use DOM manipulation methods.',
    exploitation: 'Attacker manipulates URL params to inject scripts.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'XSS_JQUERY_HTML',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via jQuery .html()',
    description: 'jQuery .html() with user input.',
    regex: /\$\s*\([^)]*\)\s*\.html\s*\(\s*(?!.*(?:sanitize|escape|DOMPurify|text\())/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Use .text() or DOMPurify.',
    exploitation: 'Attacker stores malicious HTML rendered via jQuery.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'XSS_ANGULAR_BYPASS',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via Angular Security Bypass',
    description: 'Angular bypassSecurityTrust* disables XSS protection.',
    regex: /(?:bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)|trustAs(?:Html|ResourceUrl|Js))/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Sanitize with DomSanitizer.sanitize().',
    exploitation: 'Attacker exploits trusted HTML to inject scripts.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://angular.io/guide/security#bypass-security-apis'],
  },
  {
    id: 'XSS_HREF_JAVASCRIPT',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via javascript: URL',
    description: 'javascript: protocol in href enables code execution.',
    regex: /(?:href|src|action)\s*=\s*['"]?\s*javascript\s*:/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Never use javascript: URLs.',
    exploitation: 'Attacker sets href to javascript:alert(document.cookie).',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'XSS_EVENT_HANDLER',
    severity: 'MEDIUM',
    category: 'Cross-Site Scripting',
    name: 'XSS via Dynamic Event Handlers',
    description: 'Dynamic event handler assignment with user data.',
    regex:
      /\.on(?:click|load|error|mouseover|focus|blur|submit|change|input|keydown|keyup)\s*=\s*(?!.*(?:function|=>|\bthis\b))/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Use addEventListener with function references.',
    exploitation: 'Attacker injects JS through event handlers.',
    confidence: 'LOW',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'IDOR',
    severity: 'HIGH',
    category: 'Access Control',
    name: 'Insecure Direct Object Reference',
    description: 'Direct use of user-supplied IDs without auth checks.',
    regex:
      /(?:findById|findOne|get|fetch|load)\s*\(\s*(?:req\.|params\.|query\.|ctx\.)(?:params\.|query\.|body\.)?(?:id|_id|userId|user_id)/gi,
    cwe: 'CWE-639',
    owasp: 'A01:2021-Broken Access Control',
    fix: 'Verify user owns or can access the resource.',
    exploitation: 'Attacker changes /users/123 to /users/456.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
    ],
  },
  {
    id: 'PATH_TRAVERSAL',
    severity: 'CRITICAL',
    category: 'Access Control',
    name: 'Path Traversal',
    description: 'File operations with user-controlled paths.',
    regex:
      /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|readdir|unlink|access|open)\s*\(\s*(?:path\.(?:join|resolve)\s*\()?(?:req\.|params\.|query\.|body\.|input|args|ctx\.)/gi,
    cwe: 'CWE-22',
    owasp: 'A01:2021-Broken Access Control',
    fix: 'Validate path starts with expected base directory.',
    exploitation: 'Attacker sends filename=../../../etc/passwd.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'OPEN_REDIRECT',
    severity: 'MEDIUM',
    category: 'Access Control',
    name: 'Open Redirect',
    description: 'Redirect with user-controlled URL.',
    regex:
      /(?:res\.redirect|redirect\s*\(|window\.location(?:\.href)?\s*=|location\s*(?:\.href)?\s*=|Response\.Redirect)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|url|returnUrl|next|redirect)/gi,
    cwe: 'CWE-601',
    owasp: 'A01:2021-Broken Access Control',
    fix: 'Validate redirect URLs against allowlist.',
    exploitation: 'Attacker crafts /login?redirect=https://evil.com.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
  },
  {
    id: 'CORS_WILDCARD',
    severity: 'HIGH',
    category: 'Access Control',
    name: 'CORS Wildcard Origin',
    description: 'CORS with wildcard origin.',
    regex: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['"]?\*['"]?/gi,
    cwe: 'CWE-942',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Restrict to specific trusted origins.',
    exploitation: 'Malicious site makes cross-origin requests.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html'],
  },
  {
    id: 'CORS_DYNAMIC',
    severity: 'HIGH',
    category: 'Access Control',
    name: 'CORS Dynamic Origin Reflection',
    description: 'Origin header reflected without validation.',
    regex: /(?:Access-Control-Allow-Origin|cors)\s*[:=]\s*(?:req\.headers\.origin|origin\s*\|\|\s*['"]\*['"])/gi,
    cwe: 'CWE-942',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Validate origin against allowlist.',
    exploitation: 'Attacker uses malicious site for authenticated cross-origin requests.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://portswigger.net/web-security/cors/access-control-allow-origin'],
  },
  {
    id: 'WEAK_HASH_MD5',
    severity: 'HIGH',
    category: 'Cryptography',
    name: 'Weak Hash (MD5)',
    description: 'MD5 is cryptographically broken.',
    regex:
      /(?:crypto\.createHash\s*\(\s*['"]md5['"]\)|hashlib\.md5\s*\(|MD5\.Create\s*\(\)|MessageDigest\.getInstance\s*\(\s*['"]MD5['"]\))/gi,
    cwe: 'CWE-328',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Use bcrypt/argon2 for passwords, SHA-256 for integrity.',
    exploitation: 'MD5 collisions trivial. Passwords cracked in seconds.',
    confidence: 'HIGH',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
  },
  {
    id: 'WEAK_HASH_SHA1',
    severity: 'HIGH',
    category: 'Cryptography',
    name: 'Weak Hash (SHA-1)',
    description: 'SHA-1 is deprecated.',
    regex:
      /(?:crypto\.createHash\s*\(\s*['"]sha1['"]\)|hashlib\.sha1\s*\(|SHA1\.Create\s*\(\)|MessageDigest\.getInstance\s*\(\s*['"]SHA-?1['"]\))/gi,
    cwe: 'CWE-328',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Use SHA-256 or SHA-3.',
    exploitation: 'SHA-1 collision attacks break integrity.',
    confidence: 'HIGH',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
  },
  {
    id: 'WEAK_RANDOM',
    severity: 'HIGH',
    category: 'Cryptography',
    name: 'Weak Random for Security',
    description: 'Math.random() for security operations.',
    regex:
      /(?:Math\.random|random\.random)\s*\(\s*\).*?(?:token|secret|password|key|session|auth|otp|code|pin|nonce|iv|salt)/gi,
    cwe: 'CWE-330',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Use crypto.randomBytes() or secrets module.',
    exploitation: 'Predictable random enables token forgery.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
  },
  {
    id: 'WEAK_RANDOM_GENERAL',
    severity: 'MEDIUM',
    category: 'Cryptography',
    name: 'Math.random() Usage',
    description: 'Math.random() in code with security implications.',
    regex: /Math\.random\s*\(\s*\)/gi,
    cwe: 'CWE-330',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Use crypto.randomBytes() for security.',
    exploitation: 'Math.random() outputs are predictable.',
    confidence: 'LOW',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'],
  },
  {
    id: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    category: 'Cryptography',
    name: 'Hardcoded Secret/Key',
    description: 'Hardcoded JWT secret, session secret, or encryption key.',
    regex:
      /(?:jwt[_\-]?secret|session[_\-]?secret|encryption[_\-]?key|signing[_\-]?key|SECRET_KEY|JWT_SECRET)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    cwe: 'CWE-798',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Store in env vars. Use strong random values.',
    exploitation: 'Attackers forge JWT tokens or decrypt data.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  },
  {
    id: 'WEAK_CIPHER',
    severity: 'CRITICAL',
    category: 'Cryptography',
    name: 'Weak Cipher Algorithm',
    description: 'DES, RC4, Blowfish, or ECB mode.',
    regex:
      /(?:createCipheriv?\s*\(\s*['"](?:des|rc4|bf|blowfish|ecb)|(?:DES|RC4|Blowfish|ECB)\b|(?:Cipher|cipher)\s*\(\s*['"](?:des|rc4|bf))/gi,
    cwe: 'CWE-327',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Use AES-256-GCM or ChaCha20-Poly1305.',
    exploitation: 'Weak ciphers broken with modern hardware.',
    confidence: 'HIGH',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
  },
  {
    id: 'MISSING_ENCRYPTION',
    severity: 'HIGH',
    category: 'Cryptography',
    name: 'Unencrypted HTTP Communication',
    description: 'HTTP URLs for API calls.',
    regex:
      /(?:axios|fetch|request|got|superagent|http\.get|https?\.(?:get|request)|urllib|requests)\s*(?:\(\s*)?['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/gi,
    cwe: 'CWE-319',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Use HTTPS for all external communications.',
    exploitation: 'MITM intercepts API keys and user data.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
  },
  {
    id: 'JWT_NONE_ALGORITHM',
    severity: 'CRITICAL',
    category: 'Authentication',
    name: 'JWT None Algorithm',
    description: 'JWT accepts "none" algorithm.',
    regex: /(?:algorithm|alg)\s*[:=]\s*['"](?:none|None|NONE)['"]/gi,
    cwe: 'CWE-347',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Specify allowed algorithms: { algorithms: ["HS256"] }',
    exploitation: 'Attacker forges JWT with alg:none.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
  },
  {
    id: 'JWT_WEAK_SECRET',
    severity: 'HIGH',
    category: 'Authentication',
    name: 'JWT Weak Secret',
    description: 'JWT signed with short/weak secret.',
    regex: /jwt\.sign\s*\(\s*[^,]+,\s*['"]([^'"]{1,32})['"]/gi,
    cwe: 'CWE-347',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Use strong secret (256+ bits). Prefer RS256.',
    exploitation: 'Attacker brute-forces secret with hashcat.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://auth0.com/blog/brute-forcing-jwt-secrets/'],
  },
  {
    id: 'HARDCODED_CREDENTIALS',
    severity: 'CRITICAL',
    category: 'Authentication',
    name: 'Hardcoded Credentials',
    description: 'Hardcoded username/password.',
    regex:
      /(?:user(?:name)?|login|admin)['"]?\s*[:=]\s*['"][^'"]{2,}['"].*?(?:password|passwd|pwd|pass)['"]?\s*[:=]\s*['"][^'"]{2,}['"]/gi,
    cwe: 'CWE-798',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Remove all hardcoded credentials.',
    exploitation: 'Anyone with code access authenticates as any user.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
  },
  {
    id: 'WEAK_PASSWORD_POLICY',
    severity: 'MEDIUM',
    category: 'Authentication',
    name: 'Weak Password Policy',
    description: 'Insufficient password complexity.',
    regex: /(?:password|minLength|min_length|minLen)\s*(?:[:=]|>=?)\s*(?:['"]?[0-4]['"]?|[0-4])\b/gi,
    cwe: 'CWE-521',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Enforce minimum 12 chars. Use NIST SP 800-63B.',
    exploitation: 'Weak passwords easily brute-forced.',
    confidence: 'LOW',
    vibeRisk: true,
    references: ['https://pages.nist.gov/800-63-3/sp800-63b.html'],
  },
  {
    id: 'SESSION_FIXATION',
    severity: 'HIGH',
    category: 'Authentication',
    name: 'Session Fixation',
    description: 'Session ID not regenerated after login.',
    regex:
      /(?:session|req\.session)\s*(?:\.id|\[['"](?:id|sid)['"]\])\s*(?!.*(?:regenerate|destroy|renew|invalidate))/gi,
    cwe: 'CWE-384',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Regenerate session: req.session.regenerate()',
    exploitation: 'Attacker hijacks session after victim logs in.',
    confidence: 'LOW',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
  },
  {
    id: 'DEBUG_ENABLED',
    severity: 'MEDIUM',
    category: 'Configuration',
    name: 'Debug Mode Enabled',
    description: 'Debug mode exposes internal state.',
    regex: /(?:DEBUG\s*=\s*(?:True|true|1|['"]true['"])|debug\s*[:=]\s*(?:true|1))/gi,
    cwe: 'CWE-215',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'NODE_ENV=production, DEBUG=False',
    exploitation: 'Debug exposes stack traces and env vars.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html'],
  },
  {
    id: 'CORS_PERMISSIVE',
    severity: 'HIGH',
    category: 'Configuration',
    name: 'Permissive CORS with Credentials',
    description: 'CORS wildcard + credentials.',
    regex:
      /(?:cors|CORS)\s*\(\s*\{[^}]*credentials\s*:\s*(?:true|['"]include['"])[^}]*origin\s*:\s*(?:true|\*|['"]\*['"])/gi,
    cwe: 'CWE-942',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Never combine credentials with wildcard.',
    exploitation: 'Any site makes authenticated requests.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://portswigger.net/web-security/cors/access-control-allow-origin'],
  },
  {
    id: 'DIRECTORY_LISTING',
    severity: 'MEDIUM',
    category: 'Configuration',
    name: 'Directory Listing Enabled',
    description: 'Directory listing exposes file structure.',
    regex: /(?:autoindex\s+on|directory_listing\s*(?:=|:)\s*(?:true|1|enabled))/gi,
    cwe: 'CWE-548',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Disable directory listing.',
    exploitation: 'Attackers find backup and config files.',
    confidence: 'LOW',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'],
  },
  {
    id: 'DEFAULT_CREDENTIALS',
    severity: 'CRITICAL',
    category: 'Configuration',
    name: 'Default Credentials',
    description: 'Default admin/password credentials.',
    regex: /(?:admin|root|default|test)['"]?\s*[:=]\s*['"](?:admin|password|123456|root|default|changeme|test)['"]/gi,
    cwe: 'CWE-798',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Change all default credentials.',
    exploitation: 'Default creds published in docs.',
    confidence: 'MEDIUM',
    vibeRisk: false,
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
  },
  {
    id: 'SSRF',
    severity: 'CRITICAL',
    category: 'Server-Side Request Forgery',
    name: 'Server-Side Request Forgery',
    description: 'HTTP request with user-controlled URL.',
    regex:
      /(?:fetch|axios\.(?:get|post|put|delete|patch|request)|request|got|superagent|http\.(?:get|request)|urllib|requests\.(?:get|post))\s*\(\s*(?:req\.|params\.|query\.|body\.|input|url|href|target)/gi,
    cwe: 'CWE-918',
    owasp: 'A10:2021-Server-Side Request Forgery',
    fix: 'Validate URLs. Block internal IP ranges.',
    exploitation: 'Attacker accesses http://169.254.169.254 for AWS creds.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
    ],
  },
  {
    id: 'LOG_SENSITIVE_DATA',
    severity: 'HIGH',
    category: 'Data Leakage',
    name: 'Sensitive Data in Logs',
    description: 'Logging passwords, tokens, or credit cards.',
    regex:
      /(?:console\.(?:log|warn|error|debug|info)|logger?\.(?:log|warn|error|debug|info|silly|verbose)|print|logging\.\w+)\s*\([^)]*(?:password|token|secret|key|credit.?card|ssn|social.?security)/gi,
    cwe: 'CWE-532',
    owasp: 'A09:2021-Security Logging and Monitoring Failures',
    fix: 'Never log sensitive data. Use redaction.',
    exploitation: 'Attackers extract passwords from logs.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
  },
  {
    id: 'ERROR_EXPOSURE',
    severity: 'MEDIUM',
    category: 'Data Leakage',
    name: 'Error Details to Client',
    description: 'Internal errors sent in responses.',
    regex: /res\.(?:status|json|send)\s*\(\s*(?:{[^}]*error\s*:\s*(?:err|error|e)\b|err(?:or)?\.message|err\.stack)/gi,
    cwe: 'CWE-209',
    owasp: 'A04:2021-Insecure Design',
    fix: 'Return generic: { error: "Internal server error" }',
    exploitation: 'Errors reveal tech stack and paths.',
    confidence: 'MEDIUM',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html'],
  },
  {
    id: 'COMMENT_SECRETS',
    severity: 'MEDIUM',
    category: 'Data Leakage',
    name: 'Secrets in Comments',
    description: 'Secrets in code comments.',
    regex:
      /(?:\/\/|#|\/\*|\*)\s*(?:TODO|FIXME|HACK|NOTE|TEMP|XXX|password|secret|key|token|credential)\s*:?\s*(?:.*?)(?:password|secret|key|token|api.?key|credential)\s*[:=]\s*\S+/gi,
    cwe: 'CWE-615',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Remove secrets from comments.',
    exploitation: 'Secrets persist in version control.',
    confidence: 'LOW',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  },
  {
    id: 'PROTOTYPE_POLLUTION',
    severity: 'CRITICAL',
    category: 'Supply Chain',
    name: 'Prototype Pollution',
    description: 'Object.assign with user-controlled keys.',
    regex:
      /Object\.assign\s*\(\s*(?:target|dest|obj|result|output|merged)\s*,\s*(?:req\.|params\.|query\.|body\.|input|data|source|src)|__proto__|constructor\.prototype/gi,
    cwe: 'CWE-1321',
    owasp: 'A03:2021-Injection',
    fix: 'Use Object.create(null) or Map.',
    exploitation: 'Attacker sends {"__proto__":{"isAdmin":true}}.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'PY_DESERIALIZE',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'Unsafe Deserialization (Python)',
    description: 'pickle.loads() or yaml.load() without SafeLoader.',
    regex:
      /(?:pickle\.(?:loads?|Unpickler)\s*\(|yaml\.load\s*\((?!.*(?:Loader\s*=\s*(?:yaml\.)?SafeLoader|safe_load))|marshal\.loads?\s*\()/gi,
    cwe: 'CWE-502',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    fix: 'Use yaml.safe_load(). Never pickle untrusted data.',
    exploitation: 'Crafted pickle payload achieves RCE.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'],
  },
  {
    id: 'PY_SQL_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'SQL Injection (Python)',
    description: 'SQL with f-strings or .format() in Python.',
    regex:
      /(?:execute|cursor|query)\s*\(\s*f['"]|(?:execute|cursor|query)\s*\(\s*['"][^'"]*['"]\s*\.format\s*\(|(?:execute|cursor|query)\s*\(\s*['"][^'"]*['"]\s*%\s*\(/gi,
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    fix: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    exploitation: 'Attacker sends "1; DROP TABLE users; --".',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'PY_COMMAND_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'OS Command Injection (Python)',
    description: 'os.system() or subprocess with shell=True.',
    regex:
      /(?:os\.system\s*\(|subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True|os\.popen\s*\()/gi,
    cwe: 'CWE-78',
    owasp: 'A03:2021-Injection',
    fix: 'Use subprocess.run(["ls", dir], shell=False).',
    exploitation: 'Attacker injects "; rm -rf /".',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
  },
  {
    id: 'PY_REQUESTS_VERIFY',
    severity: 'HIGH',
    category: 'Cryptography',
    name: 'Disabled TLS (Python)',
    description: 'requests with verify=False.',
    regex: /requests\.(?:get|post|put|delete|patch|head|options|request)\s*\([^)]*verify\s*=\s*False/gi,
    cwe: 'CWE-295',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Always verify TLS: verify=True.',
    exploitation: 'MITM intercepts API keys and data.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
  },
  {
    id: 'C_BUFFER_OVERFLOW',
    severity: 'CRITICAL',
    category: 'Memory Safety',
    name: 'Buffer Overflow (C/C++)',
    description: 'Unsafe C functions without bounds checking.',
    regex: /(?:strcpy|strcat|sprintf|gets|scanf)\s*\(/gi,
    cwe: 'CWE-120',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    fix: 'Use strncpy, strncat, snprintf, fgets.',
    exploitation: 'Buffer overflow for arbitrary code execution.',
    confidence: 'HIGH',
    vibeRisk: false,
    references: ['https://cwe.mitre.org/data/definitions/120.html'],
  },
  {
    id: 'C_FORMAT_STRING',
    severity: 'HIGH',
    category: 'Memory Safety',
    name: 'Format String (C/C++)',
    description: 'printf with user-controlled format string.',
    regex: /(?:printf|fprintf|sprintf|snprintf)\s*\(\s*(?!['"])/gi,
    cwe: 'CWE-134',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    fix: 'Use format string literal: printf("%s", input).',
    exploitation: '%x%x%x%n reads stack or writes memory.',
    confidence: 'MEDIUM',
    vibeRisk: false,
    references: ['https://cwe.mitre.org/data/definitions/134.html'],
  },
  {
    id: 'CS_SQL_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'SQL Injection (C#)',
    description: 'SQL with string concatenation in C#.',
    regex:
      /(?:SqlCommand|OleDbCommand|NpgsqlCommand)\s*\(\s*(?:\$|string\.Format|"|\+).*?(?:\{[0-9]*\}|\+|Request\.|param)/gi,
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    fix: 'Use parameterized queries with @id.',
    exploitation: 'Attacker injects SQL through form fields.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'CS_DESERIALIZE',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'Unsafe Deserialization (C#)',
    description: 'BinaryFormatter enables RCE.',
    regex: /(?:BinaryFormatter|JavaScriptSerializer|TypeNameHandling|ObjectStateFormatter)\s*(?:\(|\.)/gi,
    cwe: 'CWE-502',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    fix: 'Use System.Text.Json. Never BinaryFormatter.',
    exploitation: 'Crafted serialized payload achieves RCE.',
    confidence: 'HIGH',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'],
  },
  {
    id: 'CS_XSS',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS in ASP.NET',
    description: 'Response.Write or @Html.Raw with user input.',
    regex: /(?:Response\.Write\s*\(\s*(?:Request|input|param)|@Html\.Raw\s*\(|Html\.Raw\s*\()/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Use Razor encoding @Model.Property.',
    exploitation: 'Attacker injects script tags.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'CS_PATH_TRAVERSAL',
    severity: 'CRITICAL',
    category: 'Access Control',
    name: 'Path Traversal (C#)',
    description: 'Path.Combine with user input.',
    regex: /Path\.Combine\s*\(\s*[^,]+,\s*(?:Request|input|param|args)/gi,
    cwe: 'CWE-22',
    owasp: 'A01:2021-Broken Access Control',
    fix: 'Validate: Path.GetFullPath(path).StartsWith(baseDir)',
    exploitation: 'Attacker reads system files via traversal.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'GO_SQL_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'SQL Injection (Go)',
    description: 'SQL with fmt.Sprintf in Go.',
    regex: /(?:db\.Query|db\.Exec|sql\.Open).*?fmt\.Sprintf\s*\(\s*['"].*?(?:SELECT|INSERT|UPDATE|DELETE)/gi,
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    fix: 'Use parameterized queries with ?.',
    exploitation: 'Attacker modifies SQL query.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'GO_COMMAND_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'OS Command Injection (Go)',
    description: 'exec.Command with user input.',
    regex: /exec\.Command\s*\(\s*(?:["'].*?["']\s*,\s*)?(?:req\.|r\.|input|param|args|ctx\.|user)/gi,
    cwe: 'CWE-78',
    owasp: 'A03:2021-Injection',
    fix: 'Validate input against allowlist.',
    exploitation: 'Attacker injects shell commands.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
  },
  {
    id: 'GO_UNSAFE_POINTER',
    severity: 'MEDIUM',
    category: 'Memory Safety',
    name: 'unsafe.Pointer (Go)',
    description: 'unsafe.Pointer bypasses type safety.',
    regex: /unsafe\.Pointer/gi,
    cwe: 'CWE-242',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    fix: 'Avoid unsafe.Pointer.',
    exploitation: 'Type confusion or memory corruption.',
    confidence: 'LOW',
    vibeRisk: false,
    references: ['https://pkg.go.dev/unsafe#Pointer'],
  },
  {
    id: 'GO_XSS',
    severity: 'HIGH',
    category: 'Cross-Site Scripting',
    name: 'XSS via template.HTML (Go)',
    description: 'template.HTML bypasses auto-escaping.',
    regex: /template\.HTML\s*\(\s*(?:req\.|r\.|input|param|args|ctx\.|user|fmt\.Sprintf)/gi,
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    fix: 'Use template.HTML only with trusted content.',
    exploitation: 'Attacker injects HTML/JavaScript.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://pkg.go.dev/html/template#HTML'],
  },
  {
    id: 'DELPHI_SQL_INJECTION',
    severity: 'CRITICAL',
    category: 'Injection',
    name: 'SQL Injection (Delphi)',
    description: 'SQL.Text with string concatenation.',
    regex: /(?:\.SQL\.Text\s*:=|\.SQL\.Add\s*\()\s*['"].*?\+\s*(?:edt|edit|txt|input|param|variable)/gi,
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    fix: 'Use Params with ParamByName.',
    exploitation: 'Attacker injects SQL through form fields.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'DELPHI_BUFFER_OVERFLOW',
    severity: 'HIGH',
    category: 'Memory Safety',
    name: 'Buffer Overflow (Delphi)',
    description: 'PChar operations without bounds checking.',
    regex: /(?:StrCopy|StrCat|StrPCopy|StrLCopy)\s*\(/gi,
    cwe: 'CWE-120',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    fix: 'Use StrLCopy with length limits.',
    exploitation: 'Buffer overflow overwrites memory.',
    confidence: 'HIGH',
    vibeRisk: false,
    references: ['https://cwe.mitre.org/data/definitions/120.html'],
  },
  {
    id: 'DELPHI_HARDCODED_CREDENTIALS',
    severity: 'CRITICAL',
    category: 'Authentication',
    name: 'Hardcoded Connection String (Delphi)',
    description: 'DB connection string with credentials.',
    regex: /(?:Connection|ConnectionName|Database|Server)\s*['"]?\s*[:=]\s*['"].*?(?:Password|Pwd|UID)\s*[:=]/gi,
    cwe: 'CWE-798',
    owasp: 'A07:2021-Identification and Authentication Failures',
    fix: 'Store in encrypted config files.',
    exploitation: 'Anyone extracts DB credentials from source.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
  },
];

// Misconfiguration patterns scoped to config / Infrastructure-as-Code / BaaS
// files only (firestore.rules, *.tf, Dockerfile, k8s/compose YAML, ORM config,
// SQL migrations). They are intentionally NOT run on application source code to
// keep false positives low, and only fire when a file is classified as
// kind === 'config' | 'baas' by the scanner/orchestrator.
const CONFIG_MISCONFIG_PATTERNS = [
  {
    id: 'BAAS_OPEN_SECURITY_RULES',
    severity: 'CRITICAL',
    category: 'Access Control',
    name: 'Public BaaS Security Rule (allow ... if true)',
    description: 'Firebase/Firestore/Storage rule grants access unconditionally.',
    regex: /allow\s+[a-z, ]*(?:read|write|get|list|create|update|delete)[^:]*:\s*if\s+true\b/gi,
    cwe: 'CWE-284',
    owasp: 'A01:2021-Broken Access Control',
    fix: 'Scope rules with request.auth and ownership/role checks; never `if true` in production.',
    exploitation: 'Any anonymous client can read or overwrite the whole collection/bucket.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://firebase.google.com/docs/rules/rules-language'],
  },
  {
    id: 'SUPABASE_RLS_DISABLED',
    severity: 'HIGH',
    category: 'Access Control',
    name: 'Row Level Security Disabled',
    description: 'A migration disables PostgreSQL row level security on a table.',
    regex: /disable\s+row\s+level\s+security/gi,
    cwe: 'CWE-284',
    owasp: 'A01:2021-Broken Access Control',
    fix: 'Keep RLS enabled and define explicit policies; only the service role should bypass RLS server-side.',
    exploitation: 'With RLS off, any client using the anon key can read/write every row.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://supabase.com/docs/guides/database/postgres/row-level-security'],
  },
  {
    id: 'TLS_VERIFICATION_DISABLED',
    severity: 'HIGH',
    category: 'Cryptography',
    name: 'TLS Verification Disabled in Config',
    description: 'Configuration disables TLS certificate verification.',
    regex: /(?:rejectUnauthorized|ssl[_-]?verify|verify[_-]?ssl|tls[_-]?verify)\s*[:=]\s*(?:false|0|['"]false['"])/gi,
    cwe: 'CWE-295',
    owasp: 'A02:2021-Cryptographic Failures',
    fix: 'Enable certificate verification; pin or trust the proper CA instead of disabling validation.',
    exploitation: 'A man-in-the-middle can present any certificate and intercept traffic.',
    confidence: 'HIGH',
    vibeRisk: true,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
  },
  {
    id: 'OPEN_NETWORK_INGRESS',
    severity: 'HIGH',
    category: 'Security Misconfiguration',
    name: 'Network Open to the World (0.0.0.0/0)',
    description: 'Security group / firewall ingress allows any source address.',
    regex: /(?:cidr_blocks?|source_ranges|ingress|allowed_ips?|firewall)[^\n]{0,80}0\.0\.0\.0\/0/gi,
    cwe: 'CWE-284',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Restrict ingress to known IP ranges or a bastion/VPN; avoid 0.0.0.0/0 on sensitive ports.',
    exploitation: 'The service is reachable from the entire internet, widening the attack surface.',
    confidence: 'MEDIUM',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html'],
  },
  {
    id: 'STORAGE_PUBLIC_ACL',
    severity: 'HIGH',
    category: 'Access Control',
    name: 'Public Object Storage ACL',
    description: 'Object storage ACL is set to public-read or public-read-write.',
    regex: /(?:acl|x-amz-acl|access)\s*[:=]\s*['"]?public-read(?:-write)?['"]?/gi,
    cwe: 'CWE-284',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Use private ACLs with signed URLs or scoped bucket policies for controlled access.',
    exploitation: 'Anyone can list/download (or upload to) the bucket contents.',
    confidence: 'MEDIUM',
    vibeRisk: false,
    references: ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html'],
  },
  {
    id: 'CONTAINER_PRIVILEGED',
    severity: 'HIGH',
    category: 'Security Misconfiguration',
    name: 'Privileged Container',
    description: 'Container is configured to run privileged.',
    regex: /privileged\s*:\s*true/gi,
    cwe: 'CWE-250',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Drop privileged mode; grant only the specific capabilities required.',
    exploitation: 'A privileged container can escape to and compromise the host.',
    confidence: 'MEDIUM',
    vibeRisk: false,
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/'],
  },
  {
    id: 'CONTAINER_RUN_AS_ROOT',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration',
    name: 'Container Runs as Root',
    description: 'Dockerfile sets USER root (or container runs as UID 0).',
    regex: /(?:^\s*USER\s+root\b|runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0\b)/gi,
    cwe: 'CWE-250',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Create and switch to a non-root user; set runAsNonRoot: true.',
    exploitation: 'A container breakout as root maps to higher host privileges.',
    confidence: 'LOW',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'],
  },
  {
    id: 'WORLD_WRITABLE_PERMISSIONS',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration',
    name: 'World-Writable Permissions (chmod 777)',
    description: 'Build/config step grants world-writable (777) permissions.',
    regex: /chmod\s+(?:-[A-Za-z]+\s+)?0?777\b/gi,
    cwe: 'CWE-732',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Grant the least permission required (e.g. 750/640); avoid 777.',
    exploitation: 'Any local user can modify the files, enabling tampering or privilege escalation.',
    confidence: 'MEDIUM',
    vibeRisk: false,
    references: ['https://cwe.mitre.org/data/definitions/732.html'],
  },
  {
    id: 'DOCKER_UNPINNED_BASE_IMAGE',
    severity: 'LOW',
    category: 'Security Misconfiguration',
    name: 'Unpinned Base Image (:latest)',
    description: 'Dockerfile uses a floating :latest base image tag.',
    regex: /^\s*FROM\s+\S+:latest\b/gi,
    cwe: 'CWE-1104',
    owasp: 'A05:2021-Security Misconfiguration',
    fix: 'Pin a specific version or digest (FROM image@sha256:...) for reproducible, auditable builds.',
    exploitation: 'A moving base image can silently introduce vulnerable or malicious layers.',
    confidence: 'LOW',
    vibeRisk: false,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'],
  },
];

const LANGUAGE_MAP = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.java': 'java',
  '.go': 'go',
  '.rs': 'rust',
  '.php': 'php',
  '.rb': 'ruby',
  '.cs': 'csharp',
  '.c': 'c',
  '.cpp': 'cpp',
  '.h': 'c',
  '.hpp': 'cpp',
  '.pas': 'delphi',
  '.dpr': 'delphi',
  '.lpr': 'delphi',
  '.pp': 'delphi',
};

const LANGUAGE_SPECIFIC_PATTERNS = {
  python: ['PY_DESERIALIZE', 'PY_SQL_INJECTION', 'PY_COMMAND_INJECTION', 'PY_REQUESTS_VERIFY'],
  csharp: ['CS_SQL_INJECTION', 'CS_DESERIALIZE', 'CS_XSS', 'CS_PATH_TRAVERSAL'],
  go: ['GO_SQL_INJECTION', 'GO_COMMAND_INJECTION', 'GO_UNSAFE_POINTER', 'GO_XSS'],
  c: ['C_BUFFER_OVERFLOW', 'C_FORMAT_STRING'],
  cpp: ['C_BUFFER_OVERFLOW', 'C_FORMAT_STRING'],
  delphi: ['DELPHI_SQL_INJECTION', 'DELPHI_BUFFER_OVERFLOW', 'DELPHI_HARDCODED_CREDENTIALS'],
};

const LANGUAGE_SPECIFIC_PATTERN_IDS = new Set(Object.values(LANGUAGE_SPECIFIC_PATTERNS).flat());

const BINARY_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.bmp',
  '.ico',
  '.svg',
  '.webp',
  '.mp3',
  '.mp4',
  '.wav',
  '.avi',
  '.mov',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.rar',
  '.7z',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
]);

const COMPLIANCE_MAP = {
  'CWE-89': 'OWASP ASVS V5.3, GDPR Art.32, PCI DSS 6.5.1',
  'CWE-79': 'OWASP ASVS V5.3, PCI DSS 6.5.7',
  'CWE-78': 'OWASP ASVS V5.3, PCI DSS 6.5.1',
  'CWE-22': 'OWASP ASVS V12.2, PCI DSS 6.5.8',
  'CWE-798': 'OWASP ASVS V2.1, GDPR Art.32, PCI DSS 6.5.1',
  'CWE-327': 'OWASP ASVS V6.2, PCI DSS 4.1',
  'CWE-328': 'OWASP ASVS V6.2, PCI DSS 4.1',
  'CWE-330': 'OWASP ASVS V6.2',
  'CWE-502': 'OWASP ASVS V5.3',
  'CWE-918': 'OWASP ASVS V12.6',
  'CWE-943': 'OWASP ASVS V5.3',
  'CWE-347': 'OWASP ASVS V3.5',
  'CWE-601': 'OWASP ASVS V5.1',
  'CWE-611': 'OWASP ASVS V5.3',
  'CWE-95': 'OWASP ASVS V5.3',
  'CWE-1321': 'OWASP ASVS V5.3',
  'CWE-1336': 'OWASP ASVS V5.3',
  'CWE-90': 'OWASP ASVS V5.3',
  'CWE-91': 'OWASP ASVS V5.3',
  'CWE-639': 'OWASP ASVS V4.1',
  'CWE-942': 'OWASP ASVS V13.2',
  'CWE-215': 'OWASP ASVS V7.1',
  'CWE-209': 'OWASP ASVS V7.1',
  'CWE-532': 'OWASP ASVS V7.1, GDPR Art.5',
  'CWE-521': 'OWASP ASVS V2.1',
  'CWE-384': 'OWASP ASVS V3.3',
  'CWE-295': 'OWASP ASVS V9.1',
  'CWE-319': 'OWASP ASVS V9.1',
  'CWE-120': 'OWASP ASVS V5.3, CERT C STR31-C',
  'CWE-134': 'OWASP ASVS V5.3, CERT C STR31-C',
  'CWE-1333': 'OWASP ASVS V5.3',
  'CWE-615': 'OWASP ASVS V7.1',
  'CWE-693': 'OWASP ASVS V14.4',
  'CWE-548': 'OWASP ASVS V12.5',
  'CWE-242': 'OWASP ASVS V5.3',
  'CWE-284': 'OWASP ASVS V4.1',
  'CWE-250': 'OWASP ASVS V1.14',
  'CWE-732': 'OWASP ASVS V12.3',
  'CWE-1104': 'OWASP ASVS V14.2',
};

function redactSecret(value) {
  if (!value) return '[REDACTED]';
  const suffix = value.length > 4 ? value.slice(-4) : '';
  return suffix ? `[REDACTED:${value.length}:...${suffix}]` : '[REDACTED]';
}

function redactMatch(match) {
  const fullMatch = match[0];
  const capturedSecret = match.find((value, index) => index > 0 && typeof value === 'string' && value.length > 0);
  if (capturedSecret) {
    return fullMatch.replace(capturedSecret, redactSecret(capturedSecret));
  }
  return redactSecret(fullMatch);
}

function redactFindingLine(line, match) {
  const redactedMatch = redactMatch(match);
  return line.trim().replace(match[0], redactedMatch);
}

function shouldRedactPattern(pattern) {
  return (
    pattern.cwe === 'CWE-798' ||
    /secret|password|passwd|pwd|token|credential|api.?key|private.?key|access.?key|jwt.?weak.?secret/i.test(
      `${pattern.id} ${pattern.name}`,
    )
  );
}

const SAME_LINE_CONTEXT_REQUIRED = new Set(['WEAK_RANDOM_GENERAL', 'XSS_VUE_VHTML', 'GO_UNSAFE_POINTER']);

function hasSameLineRiskContext(pattern, line) {
  const text = String(line || '');
  if (pattern.id === 'WEAK_RANDOM_GENERAL') {
    return /\b(token|secret|password|key|session|auth|otp|code|pin|nonce|iv|salt)\b/i.test(text);
  }
  if (pattern.id === 'XSS_VUE_VHTML') {
    return /user|input|query|param|params|route|request|body|payload|comment|message|contentFrom|rawHtml|htmlFrom/i.test(
      text,
    );
  }
  if (pattern.id === 'GO_UNSAFE_POINTER') {
    return /user|input|param|params|request|req|body|payload|buffer|bytes|slice|reflect|uintptr/i.test(text);
  }
  return true;
}

const NON_SOURCE_PATH =
  /(?:^|[\\/])(?:tests?|__tests__|fixtures?|examples?|docs?)(?:[\\/]|$)|\.(?:test|spec)\.[A-Za-z0-9]+$|\.md$/i;

function isNonSourcePath(filePath) {
  return NON_SOURCE_PATH.test(String(filePath || ''));
}

function shouldSuppressNoisyHeuristic(pattern, line, filePath) {
  if (!SAME_LINE_CONTEXT_REQUIRED.has(pattern.id)) return false;
  if (!hasSameLineRiskContext(pattern, line)) return true;
  return isNonSourcePath(filePath);
}

function snippetAroundMatch(line, match, maxLength = 2000) {
  const text = String(line || '').trim();
  if (text.length <= maxLength) return text;
  const matchText = match?.[0] || '';
  const matchIndex = matchText ? text.indexOf(matchText) : -1;
  if (matchIndex === -1) {
    return `${text.slice(0, maxLength - 3)}...`;
  }
  const context = Math.max(0, Math.floor((maxLength - matchText.length - 6) / 2));
  const start = Math.max(0, matchIndex - context);
  const end = Math.min(text.length, matchIndex + matchText.length + context);
  const prefix = start > 0 ? '...' : '';
  const suffix = end < text.length ? '...' : '';
  return `${prefix}${text.slice(start, end)}${suffix}`;
}

export function detectSecrets(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  for (const pattern of SECRET_PATTERNS) {
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (!line) continue;

      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(line)) !== null) {
        const snippet = redactMatch(match);
        findings.push({
          id: `${pattern.id}_${findings.length}`,
          severity: pattern.severity,
          category: 'Secrets',
          name: pattern.name,
          description: pattern.description,
          file: filePath,
          line: lineIdx + 1,
          vulnerableCode: snippet,
          cwe: pattern.cwe,
          owasp: 'A07:2021-Identification and Authentication Failures',
          vibeRisk: true,
          compliance: COMPLIANCE_MAP[pattern.cwe] || '',
          fix: pattern.fix,
          confidence: 'HIGH',
          exploitation:
            'An exposed credential can be reused by anyone who can read the source code, package, logs, or generated report.',
          references: pattern.references,
        });
        if (!pattern.regex.global) break;
      }
    }
  }
  return findings;
}

function detectInContent(content, filePath, language, kind) {
  const findings = [];
  const patterns = VULNERABILITY_PATTERNS.filter((pattern) => !LANGUAGE_SPECIFIC_PATTERN_IDS.has(pattern.id));

  if (language && LANGUAGE_SPECIFIC_PATTERNS[language]) {
    for (const id of LANGUAGE_SPECIFIC_PATTERNS[language]) {
      const extra = VULNERABILITY_PATTERNS.find((p) => p.id === id);
      if (extra && !patterns.find((p) => p.id === id)) {
        patterns.push(extra);
      }
    }
  }

  // Config / IaC / BaaS misconfiguration patterns are scoped to those file kinds
  // to keep false positives off application source code.
  if (kind === 'config' || kind === 'baas') {
    patterns.push(...CONFIG_MISCONFIG_PATTERNS);
  }

  const lines = content.split('\n');

  for (const pattern of patterns) {
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (!line || line.length > 2000) continue;

      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(line)) !== null) {
        if (shouldSuppressNoisyHeuristic(pattern, line, filePath)) {
          if (!pattern.regex.global) break;
          continue;
        }
        findings.push({
          id: `${pattern.id}_${findings.length}`,
          severity: pattern.severity,
          category: pattern.category,
          name: pattern.name,
          description: pattern.description,
          file: filePath,
          line: lineIdx + 1,
          vulnerableCode: shouldRedactPattern(pattern)
            ? redactFindingLine(line, match)
            : snippetAroundMatch(line, match),
          cwe: pattern.cwe,
          owasp: pattern.owasp,
          vibeRisk: pattern.vibeRisk,
          compliance: COMPLIANCE_MAP[pattern.cwe] || '',
          fix: pattern.fix,
          confidence: pattern.confidence,
          exploitation: pattern.exploitation,
          references: pattern.references,
        });
        if (!pattern.regex.global) break;
      }
    }
  }
  return findings;
}

export function detectVulnerabilities(projectInfo) {
  const allFindings = [];

  if (!projectInfo || !Array.isArray(projectInfo.files)) {
    return allFindings;
  }

  for (const file of projectInfo.files) {
    if (!file || !file.path) continue;

    const ext = file.path.slice(file.path.lastIndexOf('.')).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;

    const language = file.language && file.language !== 'unknown' ? file.language : LANGUAGE_MAP[ext] || null;

    let content;
    let isMinified;
    try {
      const absolutePath = projectInfo.root ? safeResolveInside(projectInfo.root, file.path) : file.path;
      if (!absolutePath) continue;
      const result = readFileSafe(absolutePath);
      if (!result || result.isBinary || !result.content) continue;
      content = result.content;
      isMinified = Boolean(result.isMinified);
    } catch {
      continue;
    }
    if (!content || typeof content !== 'string') continue;

    const secretFindings = detectSecrets(content, file.path);
    allFindings.push(...secretFindings);

    if (isMinified) continue;

    const vulnFindings = detectInContent(content, file.path, language, file.kind);
    allFindings.push(...vulnFindings);
  }

  allFindings.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 99;
    const sb = SEVERITY_ORDER[b.severity] ?? 99;
    return sa - sb;
  });

  return allFindings;
}

export { SECRET_PATTERNS, VULNERABILITY_PATTERNS, CONFIG_MISCONFIG_PATTERNS, COMPLIANCE_MAP };
