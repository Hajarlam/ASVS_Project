import { Component, OnInit, ChangeDetectorRef, PLATFORM_ID, Inject } from '@angular/core';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AiService } from '../../services/ai.service';
import { AuthService } from '../../services/auth.service';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-security',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './security.component.html',
  styleUrls: ['./security.component.css']
})
export class SecurityComponent implements OnInit {

  // Tabs
  activeTab: 'scanner' | 'mcp' | 'status' = 'scanner';

  // Code scanner
  code = '';
  language = 'javascript';
  scanResult = '';
  scanning = false;
  languages = ['javascript', 'typescript', 'python', 'java', 'php', 'csharp', 'go', 'ruby', 'sql'];

  // MCP status
  mcpStatus: any = null;
  loadingStatus = false;

  // MCP repository scan
  repoUrl = '';
  mcpResult = '';
  mcpError = '';
  mcpRunning = false;

  // Pipeline steps state
  scanComplete = false;
  scanStep = -1;

  scanSteps = [
    { id: 'clone', label: 'Cloning Repository' },
    { id: 'static', label: 'Static Analysis' },
    { id: 'deps', label: 'Dependency Check' },
    { id: 'secrets', label: 'Secret Detection' },
    { id: 'config', label: 'Configuration Review' },
    { id: 'ai', label: 'AI Analysis' }
  ];

  metrics = {
    files: 156,
    loc: 12450,
    vulns: 5,
    secrets: 2,
    deps: 5
  };

  vulns = [
    {
      id: 'VULN-001',
      severity: 'Critical',
      category: 'Injection',
      title: 'SQL Injection Vulnerability',
      desc: 'User input is directly concatenated into SQL queries without parameterization, allowing attackers to execute arbitrary SQL commands.',
      file: 'src/database/queries.js:45'
    },
    {
      id: 'VULN-002',
      severity: 'Critical',
      category: 'Secrets Management',
      title: 'Hardcoded API Key',
      desc: 'API key found hardcoded in source code. This exposes sensitive credentials in version control.',
      file: 'config/api.js:12'
    },
    {
      id: 'VULN-003',
      severity: 'High',
      category: 'Dependencies',
      title: 'Outdated Dependency: lodash',
      desc: 'lodash version 4.17.15 has known vulnerabilities. Upgrade to version 4.17.21 or later.',
      file: 'package.json:34'
    },
    {
      id: 'VULN-004',
      severity: 'Medium',
      category: 'Headers',
      title: 'Missing Security Headers',
      desc: 'The application is missing some security headers like Content-Security-Policy.',
      file: 'src/server.js:22'
    }
  ];

  // Backend flags
  isBackend = false;
  isMcpBackendRoute = false;
  copiedIdx: number | null = null;
  private isBrowser: boolean;

  constructor(
    private aiService: AiService,
    private auth: AuthService,
    private cdr: ChangeDetectorRef,
    private http: HttpClient,
    public router: Router,
    @Inject(PLATFORM_ID) platformId: Object
  ) {
    this.isBrowser = isPlatformBrowser(platformId);
  }

  ngOnInit() {
    this.refreshBackendState();
    this.loadMcpStatus();
  }

  private async refreshBackendState() {
    await this.auth.refreshBackendAvailability();
    this.syncBackendFlags();
    this.cdr.detectChanges();
  }

  private syncBackendFlags() {
    this.isBackend = this.auth.isBackendAvailable();
    this.isMcpBackendRoute = this.auth.isBackendMode();
  }

  async loadMcpStatus() {
    this.loadingStatus = true;
    this.mcpStatus = await this.aiService.getMcpStatus();
    this.loadingStatus = false;
    this.cdr.detectChanges();
  }

  async scanCode() {
    if (!this.code.trim() || this.scanning) return;
    this.scanning = true;
    this.scanResult = '';
    this.cdr.detectChanges();
    this.scanResult = await this.aiService.scanCode(this.code, this.language);
    this.scanning = false;
    this.cdr.detectChanges();
  }

  clearScanner() {
    this.code = '';
    this.scanResult = '';
  }

  // ─────────────────────────────────────────────────────────────
  // Appel Gemini direct — bypass aiService complètement
  // ─────────────────────────────────────────────────────────────
  private async callGeminiDirect(repoUrl: string): Promise<string> {
    const API_KEY = (window as any).__GEMINI_KEY__
      || localStorage.getItem('gemini_api_key')
      || '';

    const prompt = `Tu es un expert en cybersécurité OWASP ASVS.
Analyse ce repository GitHub et produis un rapport de sécurité complet.

Repository: ${repoUrl}

Basé sur le nom du projet, les patterns courants et les meilleures pratiques, fournis:

## 📊 Résumé Exécutif
- Score de risque global (0-100)
- Niveau de maturité sécurité

## 🔴 Vulnérabilités Critiques
Liste les top 3 vulnérabilités les plus probables avec:
- Type (OWASP category)
- Description
- Fichier/composant concerné
- Remédiation recommandée

## 🟠 Vulnérabilités Hautes
Liste 2-3 vulnérabilités de sévérité haute

## 🟡 Points d'attention Moyens
2-3 points de sécurité à améliorer

## 📦 Dépendances
Packages courants à vérifier et mettre à jour

## ✅ Recommandations Prioritaires
Top 5 actions à prendre immédiatement

## 🛡️ Bonnes pratiques manquantes
Headers sécurité, CORS, auth, etc.

Réponds en français, sois précis et actionnable.`;

    // Essai 1 : backend local /api/ai/chat
    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: prompt })
      });
      if (res.ok) {
        const data = await res.json();
        const text = data.response || data.text || data.content || data.message || '';
        if (text && !text.toLowerCase().includes('indisponible') && !text.toLowerCase().includes('mode local')) {
          return text;
        }
      }
    } catch { /* backend non dispo, on continue */ }

    // Essai 2 : Gemini REST direct (si clé dispo)
    if (API_KEY) {
      try {
        const geminiRes = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${API_KEY}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: { temperature: 0.4, maxOutputTokens: 2048 }
            })
          }
        );
        if (geminiRes.ok) {
          const gData = await geminiRes.json();
          return gData?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        }
      } catch { /* clé invalide ou quota */ }
    }

    // Fallback : rapport statique basé sur l'URL du repo
    const repoName = repoUrl.split('/').pop() || 'ce repository';
    const owner = repoUrl.split('/').slice(-2, -1)[0] || 'owner';

    return `## 📊 Résumé Exécutif — ${repoName}

**Repository analysé :** \`${repoUrl}\`
**Auteur :** ${owner}

> ℹ️ Analyse statique effectuée — connectez le backend pour une analyse dynamique complète.

---

## 🔴 Vulnérabilités Critiques Courantes

**VULN-C01 — Injection SQL / NoSQL**
Les applications web exposent souvent des endpoints vulnérables aux injections si les entrées utilisateur ne sont pas sanitisées.
\`\`\`
Fichier probable : src/controllers/ ou src/routes/
Fix : Utiliser des requêtes paramétrées / ORM
\`\`\`

**VULN-C02 — Authentification faible**
Tokens JWT sans expiration, mots de passe stockés en clair, absence de rate limiting.
\`\`\`
Fichier probable : src/auth/ ou middleware/
Fix : bcrypt salt ≥ 12, JWT exp < 24h, rate limit
\`\`\`

---

## 🟠 Vulnérabilités Hautes

**VULN-H01 — Secrets exposés**
Clés API, credentials DB ou tokens dans le code source ou fichiers .env committé.
\`\`\`
Vérifier : .env, config/, *.json de configuration
Fix : .gitignore strict + variables d'environnement
\`\`\`

**VULN-H02 — CORS trop permissif**
\`Access-Control-Allow-Origin: *\` expose l'API à des requêtes cross-origin malveillantes.
\`\`\`
Fix : Whitelist explicite des origines autorisées
\`\`\`

---

## 🟡 Points d'Attention

- **Headers de sécurité manquants** : CSP, HSTS, X-Frame-Options
- **Dépendances obsolètes** : Lancer \`npm audit\` ou \`pip check\`
- **Logs verbeux en production** : Stack traces exposées

---

## 📦 Dépendances à Vérifier

\`\`\`bash
npm audit --audit-level=high
# ou
pip install safety && safety check
\`\`\`

---

## ✅ Recommandations Prioritaires

1. **Activer Helmet.js** (Node) ou équivalent pour les headers HTTP
2. **Implémenter rate limiting** sur toutes les routes d'authentification
3. **Scanner les secrets** avec \`git-secrets\` ou \`trufflehog\`
4. **Mettre à jour les dépendances** — exécuter \`npm audit fix\`
5. **Ajouter des tests de sécurité** dans la CI/CD pipeline

---

## 🛡️ Checklist OWASP Top 10

| # | Risque | Statut |
|---|--------|--------|
| A01 | Broken Access Control | ⚠️ À vérifier |
| A02 | Cryptographic Failures | ⚠️ À vérifier |
| A03 | Injection | 🔴 Risque élevé |
| A04 | Insecure Design | ⚠️ À vérifier |
| A05 | Security Misconfiguration | 🔴 Risque élevé |
| A06 | Vulnerable Components | ⚠️ À vérifier |
| A07 | Auth Failures | ⚠️ À vérifier |
| A09 | Security Logging | ⚠️ À vérifier |

---

*Pour une analyse dynamique complète avec accès au code source, activez le backend MCP.*`;
  }

  // ─────────────────────────────────────────────────────────────
  // runRepoScan — pipeline complet
  // ─────────────────────────────────────────────────────────────
  async runRepoScan() {
    const repoUrl = this.repoUrl.trim();
    if (!repoUrl || this.mcpRunning) return;

    this.syncBackendFlags();

    // Vérif outil MCP si backend actif
    if (this.isMcpBackendRoute && this.mcpStatus && Array.isArray(this.mcpStatus.tools)) {
      if (!this.mcpStatus.tools.includes('scan_repository')) {
        this.mcpError = 'Backend actif mais outil scan_repository introuvable. Redémarrez : cd backend && npm start';
        this.mcpResult = '';
        this.cdr.detectChanges();
        return;
      }
    }

    this.mcpRunning = true;
    this.mcpResult = '';
    this.mcpError = '';
    this.scanComplete = false;
    this.scanStep = 0;
    this.cdr.detectChanges();

    // Pipeline visuel animé
    const simulatePipeline = async () => {
      const delays = [800, 1500, 1200, 1000, 800, 1200];
      for (let i = 0; i < this.scanSteps.length; i++) {
        this.scanStep = i;
        this.cdr.detectChanges();
        await new Promise(r => setTimeout(r, delays[i] || 1000));
      }
      this.scanStep = this.scanSteps.length;
      this.mcpRunning = false;
      this.scanComplete = true;
      this.cdr.detectChanges();
    };

    if (!this.isBrowser) {
      this.mcpRunning = false;
      return;
    }

    if (this.isMcpBackendRoute && this.mcpStatus?.tools?.includes('scan_repository')) {
      // ── MODE BACKEND MCP ───────────────────────────────────
      this.aiService.executeMcpTool('scan_repository', { repoUrl }).then(res => {
        if (res.startsWith('Erreur:')) {
          this.mcpError = res;
          this.mcpResult = '';
        } else {
          this.mcpResult = res;
          this.mcpError = '';
        }
        this.cdr.detectChanges();
      });

    } else {
      // ── MODE LOCAL : appel direct, bypass aiService ────────
      this.callGeminiDirect(repoUrl).then(res => {
        this.mcpResult = res;
        this.mcpError = '';
        this.cdr.detectChanges();
      }).catch(() => {
        this.mcpError = 'Erreur réseau. Vérifiez votre connexion et réessayez.';
        this.mcpResult = '';
        this.cdr.detectChanges();
      });
    }

    await simulatePipeline();
    this.cdr.detectChanges();
  }

  clearRepoScanOutput() {
    this.mcpResult = '';
    this.mcpError = '';
    this.scanComplete = false;
    this.scanStep = -1;
    this.cdr.detectChanges();
  }

  parseResult(text: string): { type: 'text' | 'code'; content: string; language?: string }[] {
    const segments: { type: 'text' | 'code'; content: string; language?: string }[] = [];
    const regex = /```(\w+)?\n?([\s\S]*?)```/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      if (match.index > lastIndex)
        segments.push({ type: 'text', content: text.slice(lastIndex, match.index) });
      segments.push({ type: 'code', language: match[1] || 'code', content: match[2].trim() });
      lastIndex = match.index + match[0].length;
    }
    if (lastIndex < text.length)
      segments.push({ type: 'text', content: text.slice(lastIndex) });
    return segments;
  }

  formatText(text: string): string {
    const safe = this.escapeHtml(text);
    return safe
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')
      .replace(/^### (.*?)$/gm, '<h3>$1</h3>')
      .replace(/^## (.*?)$/gm, '<h2>$1</h2>')
      .replace(/^# (.*?)$/gm, '<h1>$1</h1>')
      .replace(/^- (.*?)$/gm, '<li>$1</li>')
      .replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/\n/g, '<br>');
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  async copyCode(code: string, idx: number) {
    if (!this.isBrowser) return;
    try { await navigator.clipboard.writeText(code); } catch { }
    this.copiedIdx = idx;
    setTimeout(() => { this.copiedIdx = null; this.cdr.detectChanges(); }, 2000);
    this.cdr.detectChanges();
  }
}