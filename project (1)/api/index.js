import crypto from 'crypto';

// ============================================================
// KV STORE (Upstash REST API — works with Vercel KV)
// ============================================================
const _mem = globalThis.__memStore || (globalThis.__memStore = new Map());
const hasKV = () => !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);

async function kvSetex(key, ttl, value) {
  if (hasKV()) {
    const res = await fetch(`${process.env.KV_REST_API_URL}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(['SETEX', key, String(ttl), value]),
    });
    return res.json();
  }
  _mem.set(key, { value, expiry: Math.floor(Date.now() / 1000) + ttl });
}

async function kvGet(key) {
  if (hasKV()) {
    const res = await fetch(`${process.env.KV_REST_API_URL}/get/${encodeURIComponent(key)}`, {
      headers: { Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}` },
    });
    const data = await res.json();
    return data.result;
  }
  const v = _mem.get(key);
  if (!v) return null;
  if (v.expiry && v.expiry < Date.now() / 1000) { _mem.delete(key); return null; }
  return v.value;
}

// ============================================================
// OBFUSCATOR (JS port — lexer, string enc, number mba, rename)
// ============================================================
const ID_S = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
const ID_C = ID_S + '0123456789';

const randIdent = (min = 6, max = 10) => {
  const n = min + Math.floor(Math.random() * (max - min + 1));
  let s = ID_S[Math.floor(Math.random() * ID_S.length)];
  for (let i = 1; i < n; i++) s += ID_C[Math.floor(Math.random() * ID_C.length)];
  return s;
};

const xorBytes = (str, key) =>
  Array.from(str, (ch, i) => ch.charCodeAt(0) ^ key[i % key.length]);

const KEYWORDS = new Set('and break do else elseif end false for function if in local nil not or repeat return then true until while continue type export'.split(' '));
const SYMS = '... ..= == ~= <= >= //= :: -> += -= *= /= %= ^= .. // = < > + - * / % ^ # & | ~ ( ) { } [ ] , ; : . ?'.split(' ').sort((a, b) => b.length - a.length);

function lex(src) {
  const out = []; let pos = 0, len = src.length;
  while (pos < len) {
    const c = src[pos], s = pos;
    if (/\s/.test(c)) {
      let e = pos; while (e < len && /\s/.test(src[e])) e++;
      out.push({ t: 'space', v: src.slice(s, e) }); pos = e;
    } else if (c === '-' && src[pos + 1] === '-') {
      let e = pos + 2;
      const m = src.slice(e).match(/^\[(=*)\[/);
      if (m) {
        const close = ']' + m[1] + ']';
        const idx = src.indexOf(close, e + 2 + m[1].length);
        e = idx >= 0 ? idx + close.length : len;
      } else while (e < len && src[e] !== '\n') e++;
      out.push({ t: 'comment', v: src.slice(s, e) }); pos = e;
    } else if (c === '[' && (src[pos + 1] === '[' || src[pos + 1] === '=')) {
      const m = src.slice(pos).match(/^\[(=*)\[/);
      if (m) {
        const close = ']' + m[1] + ']';
        const idx = src.indexOf(close, pos + 2 + m[1].length);
        const e = idx >= 0 ? idx + close.length : len;
        out.push({ t: 'longstr', v: src.slice(s, e) }); pos = e;
      } else { out.push({ t: 'sym', v: '[' }); pos = s + 1; }
    } else if (c === '"' || c === "'") {
      let e = pos + 1;
      while (e < len) { const ch = src[e]; if (ch === '\\') e += 2; else if (ch === c) { e++; break; } else e++; }
      out.push({ t: 'str', v: src.slice(s, e) }); pos = e;
    } else if (/[a-zA-Z_]/.test(c)) {
      let e = pos; while (e < len && /[a-zA-Z0-9_]/.test(src[e])) e++;
      const v = src.slice(s, e);
      out.push({ t: KEYWORDS.has(v) ? 'kw' : 'name', v }); pos = e;
    } else if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(src[pos + 1] || ''))) {
      let e = pos; while (e < len && /[0-9a-zA-Z.]/.test(src[e])) e++;
      out.push({ t: 'num', v: src.slice(s, e) }); pos = e;
    } else {
      let hit = false;
      for (const sym of SYMS) if (src.slice(pos, pos + sym.length) === sym) {
        out.push({ t: 'sym', v: sym }); pos += sym.length; hit = true; break;
      }
      if (!hit) { out.push({ t: 'sym', v: c }); pos = s + 1; }
    }
  }
  return out;
}

function unescapeStr(s) {
  return s.replace(/\\(x[0-9a-fA-F]{2}|.)/g, (_, c) => {
    if (c.startsWith('x')) return String.fromCharCode(parseInt(c.slice(1), 16));
    return { n: '\n', t: '\t', r: '\r', '0': '\0', '\\': '\\', '"': '"', "'": "'" }[c] || c;
  });
}

function fixMissingEquals(toks) {
  const out = []; let i = 0;
  while (i < toks.length) {
    const tok = toks[i];
    if (tok.t === 'kw' && tok.v === 'local') {
      out.push(tok); i++;
      while (i < toks.length && toks[i].t === 'space') { out.push(toks[i]); i++; }
      let seenName = false;
      while (i < toks.length && toks[i].t === 'name') {
        out.push(toks[i]); i++; seenName = true;
        while (i < toks.length && toks[i].t === 'space') { out.push(toks[i]); i++; }
        if (i < toks.length && toks[i].t === 'sym' && toks[i].v === ',') {
          out.push(toks[i]); i++;
          while (i < toks.length && toks[i].t === 'space') { out.push(toks[i]); i++; }
        } else break;
      }
      if (seenName && i < toks.length && (toks[i].t === 'str' || toks[i].t === 'num')) {
        out.push({ t: 'sym', v: '=' }, { t: 'space', v: ' ' });
      }
    } else { out.push(tok); i++; }
  }
  return out;
}

function encryptStrings(toks, key) {
  const strings = [];
  toks.forEach((tok, i) => { if (tok.t === 'str') strings.push({ idx: i, plain: unescapeStr(tok.v.slice(1, -1)) }); });
  if (strings.length === 0) return '';
  const enc = strings.map(s => xorBytes(s.plain, key));
  strings.forEach((s, i) => { toks[s.idx].t = 'name'; toks[s.idx].v = `__S(${i + 1})`; });
  const K = '__' + randIdent(3, 5), D = '__' + randIdent(3, 5), C = '__' + randIdent(3, 5), S = '__' + randIdent(3, 5);
  return [
    `local ${K}={${key.join(',')}}`,
    `local ${D}={${enc.map(a => `{${a.join(',')}}`).join(',')}}`,
    `local ${C}={}`,
    `local function ${S}(i) if ${C}[i] then return ${C}[i] end local d=${D}[i] local t={} for j=1,#d do t[j]=string.char(bit32.bxor(d[j],${K}[(j-1)%#${K}+1])) end ${C}[i]=table.concat(t) return ${C}[i] end`,
  ].join(' ');
}

function obfuscateNumbers(toks) {
  for (const tok of toks) if (tok.t === 'num' && !isNaN(Number(tok.v))) {
    const a = 1 + Math.floor(Math.random() * 500);
    tok.v = `(${tok.v}+${a}-${a})`;
  }
}

function renameLocals(toks) {
  const scopes = [{}];
  const declare = n => { const nn = '__' + randIdent(6, 10); scopes[scopes.length - 1][n] = nn; return nn; };
  const lookup = n => { for (let i = scopes.length - 1; i >= 0; i--) if (scopes[i][n]) return scopes[i][n]; return null; };
  let i = 0;
  while (i < toks.length) {
    const tok = toks[i];
    if (tok.t === 'kw') {
      if (tok.v === 'local') {
        let j = i + 1;
        while (j < toks.length && toks[j].t === 'space') j++;
        if (j < toks.length && toks[j].t === 'kw' && toks[j].v === 'function') {
          j++; while (j < toks.length && toks[j].t === 'space') j++;
          if (j < toks.length && toks[j].t === 'name') toks[j].v = declare(toks[j].v);
          scopes.push({}); i = j + 1;
        } else {
          while (j < toks.length) {
            const t = toks[j];
            if (t.t === 'name') {
              t.v = declare(t.v); j++;
              while (j < toks.length && toks[j].t === 'space') j++;
              if (j < toks.length && toks[j].t === 'sym' && toks[j].v === ',') {
                j++; while (j < toks.length && toks[j].t === 'space') j++;
              } else break;
            } else break;
          }
          i = j;
        }
      } else if (['function', 'do', 'then', 'repeat'].includes(tok.v)) { scopes.push({}); i++; }
      else if (['else', 'elseif'].includes(tok.v)) { if (scopes.length > 1) scopes.pop(); scopes.push({}); i++; }
      else if (['end', 'until'].includes(tok.v)) { if (scopes.length > 1) scopes.pop(); i++; }
      else i++;
    } else if (tok.t === 'name') {
      let prev = i - 1;
      while (prev >= 0 && toks[prev].t === 'space') prev--;
      const isAccess = prev >= 0 && toks[prev].t === 'sym' && (toks[prev].v === '.' || toks[prev].v === ':');
      if (!isAccess) { const nn = lookup(tok.v); if (nn) tok.v = nn; }
      i++;
    } else i++;
  }
}

const needsSpace = (p, c) => {
  const w = t => ['name', 'kw', 'num'].includes(t.t);
  if (w(p) && w(c)) return true;
  if (p.t === 'sym' && c.t === 'sym') {
    if (p.v === '-' && c.v === '-') return true;
    if (p.v === '.' && c.v === '.') return true;
  }
  if (p.t === 'num' && c.t === 'sym' && (c.v === '..' || c.v[0] === '.')) return true;
  return false;
};

function compact(toks) {
  const out = []; let prev = null;
  for (const t of toks) {
    if (t.t === 'space' || t.t === 'comment') continue;
    if (prev && needsSpace(prev, t)) out.push(' ');
    out.push(t.v); prev = t;
  }
  return out.join('');
}

function obfuscate(source, key) {
  let toks = lex(source);
  toks = fixMissingEquals(toks);
  const preamble = encryptStrings(toks, key);
  obfuscateNumbers(toks);
  renameLocals(toks);
  return preamble + ' ' + compact(toks);
}

// ============================================================
// LOADER GENERATOR (stage 1)
// ============================================================
function generateLoader(baseUrl, buildId) {
  const a = '__' + randIdent(5, 7);
  const h = '__' + randIdent(5, 7);
  const r = '__' + randIdent(5, 7);
  const ok = '__' + randIdent(5, 7);
  const b = '__' + randIdent(5, 7);
  const f = '__' + randIdent(5, 7);
  return [
    `local ${a}=game:GetService("HttpService")`,
    `local ${h}=""`,
    `pcall(function()${h}=game:GetService("RbxAnalyticsService"):GetClientId() end)`,
    `local ${ok},${r}=pcall(function()return ${a}:RequestAsync({Url="${baseUrl}?action=stage2&build=${buildId}&hw="..${h},Method="GET"})end)`,
    `if not ${ok} or not ${r}.Success then return end`,
    `local ${b}=${r}.Body`,
    `if not ${b} or #${b}<16 then return end`,
    `local ${f}=loadstring(${b})`,
    `if ${f} then pcall(${f}) end`,
  ].join('\n');
}

// ============================================================
// STAGE 2 SILENT-FAILURE DUMMY (returned on HWID mismatch)
// ============================================================
function dummyStage2() {
  const x = '__' + randIdent(4, 6);
  return `local ${x}={0,0,0,0} local function __S(i)return string.char(${x}[i]or 0)end;__S(1);`;
}

// ============================================================
// HTML UI
// ============================================================
const HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Luau Obfuscator</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#0e0e15;color:#d0d0e0;min-height:100vh}
.hdr{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:18px 32px;border-bottom:1px solid #2a2a3e}
.hdr h1{margin:0;font-size:20px;color:#e0e0f0}.hdr p{margin:4px 0 0;font-size:12px;color:#8080a0}
.wrap{max-width:1400px;margin:20px auto;padding:0 20px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.panel{background:#161622;border:1px solid #262636;border-radius:10px;overflow:hidden}
.panel .ph{padding:8px 12px;background:#1c1c2e;border-bottom:1px solid #262636;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#8080a0;font-weight:600}
textarea{width:100%;height:360px;padding:12px;border:0;background:#12121c;color:#d0d0e0;font-family:Consolas,Monaco,monospace;font-size:13px;resize:vertical;outline:none}
.ctrl{display:flex;gap:10px;align-items:center;margin:16px 0;flex-wrap:wrap}
input[type=text]{padding:9px 13px;background:#12121c;border:1px solid #262636;border-radius:6px;color:#d0d0e0;font-size:13px;min-width:280px}
button{padding:9px 18px;border:0;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.85}button:disabled{opacity:.5;cursor:wait}
.bp{background:#4a7dd4;color:#fff}.bs{background:#3a9f5a;color:#fff}.bd{background:#a04444;color:#fff}
.sm{padding:5px 10px;font-size:11px}
.status{font-size:13px;padding:6px 12px;border-radius:6px;display:none}
.status.info{display:inline-block;background:#1e2a4e;color:#8ab4f8}
.status.err{display:inline-block;background:#4a1e1e;color:#f8a8a8}
.status.ok{display:inline-block;background:#1e3a2a;color:#a8f8b8}
.result{display:none;margin-top:16px}.result.active{display:block}
.ritem{background:#161622;border:1px solid #262636;border-radius:10px;margin-bottom:10px;padding:12px 14px}
.ritem h3{margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#8080a0;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.cb{background:#0d0d16;border-radius:6px;padding:10px;font-family:Consolas,Monaco,monospace;font-size:12px;color:#a0d0b0;white-space:pre;overflow:auto;max-height:200px}
.meta{font-size:11px;color:#8080a0;margin-bottom:4px}.meta strong{color:#c0c0e0}
.hist{margin-top:20px}.hist h2{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:#8080a0;margin:0 0 10px}
.hitem{background:#161622;border:1px solid #262636;border-radius:6px;padding:8px 12px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;font-size:12px}
.hitem .id{font-family:Consolas,monospace;color:#8ab4f8}.hitem .dt{color:#8080a0;margin-left:10px}
.hitem button{padding:4px 10px;font-size:11px}
</style></head><body>
<div class="hdr"><h1>Luau Obfuscator</h1><p>Per-build keys · HWID lock · Two-stage loader · Server-side obfuscation</p></div>
<div class="wrap">
<div class="grid">
<div class="panel"><div class="ph">Input Source</div><textarea id="in" placeholder="Paste your Luau code here..."></textarea></div>
<div class="panel"><div class="ph">Stage 2 Preview (server-side only)</div><textarea id="prev" readonly placeholder="Output appears after you click Obfuscate..."></textarea></div>
</div>
<div class="ctrl">
<input type="text" id="hw" placeholder="Optional HWID lock (leave empty = no lock)">
<button class="bp" id="go">Obfuscate</button>
<span class="status" id="st"></span>
</div>
<div class="result" id="res">
<div class="ritem">
<h3><span>Loader Script — paste this in Roblox</span><button class="bs sm" onclick="cp('loader')">Copy</button></h3>
<div class="meta">Build ID: <strong id="bid"></strong> · Expires: <strong id="exp"></strong> · HWID Locked: <strong id="lock"></strong></div>
<div class="cb" id="loader"></div>
</div>
<div class="ritem">
<h3><span>Stage 2 (full obfuscated script)</span><button class="bs sm" onclick="cp('stage2')">Copy</button></h3>
<div class="meta">Size: <strong id="sz"></strong></div>
<div class="cb" id="stage2"></div>
</div>
</div>
<div class="hist"><h2>Recent Builds (this browser)</h2><div id="histList"></div></div>
</div>
<script>
const $=id=>document.getElementById(id);
let loader='',stage2='';
function st(m,c){$('st').textContent=m;$('st').className='status '+(c||'info');}
function cp(t){const v=t==='loader'?loader:stage2;navigator.clipboard.writeText(v).then(()=>st('Copied!','ok'));}
function loadHist(){
  const h=JSON.parse(localStorage.getItem('builds')||'[]');
  const el=$('histList');
  if(!h.length){el.innerHTML='<div class="hitem" style="justify-content:center;color:#505070">No builds yet</div>';return;}
  el.innerHTML=h.slice(0,10).map(b=>'<div class="hitem"><div><span class="id">'+b.buildId+'</span><span class="dt">'+new Date(b.createdAt*1000).toLocaleString()+'</span></div><button class="bs sm" onclick="reuse(\''+b.buildId+'\')">Copy Loader</button></div>').join('');
}
function reuse(bid){
  const h=JSON.parse(localStorage.getItem('builds')||'[]');
  const b=h.find(x=>x.buildId===bid);
  if(b){loader=b.loader;navigator.clipboard.writeText(b.loader);st('Loader copied!','ok');}
}
$('go').onclick=async()=>{
  const src=$('in').value.trim();
  if(!src){st('Paste some code first.','err');return;}
  $('go').disabled=true;st('Obfuscating...','info');
  try{
    const r=await fetch('/?action=obfuscate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:src,hwid:$('hw').value.trim()||null})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'failed');
    loader=d.loader;stage2=d.stage2;
    $('bid').textContent=d.buildId;
    $('exp').textContent=new Date(d.expiresAt*1000).toLocaleString();
    $('lock').textContent=d.hwidLocked?'Yes':'No';
    $('loader').textContent=d.loader;
    $('stage2').textContent=d.stage2;
    $('sz').textContent=d.stage2.length+' bytes';
    $('prev').value=d.stage2;
    $('res').classList.add('active');
    const hist=JSON.parse(localStorage.getItem('builds')||'[]');
    hist.unshift({buildId:d.buildId,createdAt:Math.floor(Date.now()/1000),loader:d.loader});
    localStorage.setItem('builds',JSON.stringify(hist.slice(0,20)));
    loadHist();
    st('Done! Copy the loader and paste it in Roblox.','ok');
  }catch(e){st('Error: '+e.message,'err');}
  finally{$('go').disabled=false;}
};
loadHist();
</script></body></html>`;

// ============================================================
// HANDLER
// ============================================================
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const url = new URL(req.url, `https://${req.headers.host}`);
  const action = url.searchParams.get('action');

  // --- POST ?action=obfuscate ---
  if (req.method === 'POST' && action === 'obfuscate') {
    try {
      const body = await readJSON(req);
      const source = body.source;
      const hwid = body.hwid || null;

      if (!source || typeof source !== 'string') return res.status(400).json({ error: 'source is required' });
      if (source.length > 500_000) return res.status(413).json({ error: 'source too large' });

      const key = Array.from(crypto.randomBytes(16));
      const obfuscated = obfuscate(source, key);
      const buildId = crypto.randomBytes(12).toString('hex');
      const ttl = 86400;

      await kvSetex(`build:${buildId}`, ttl, JSON.stringify({ obfuscated, hwidLock: hwid }));

      const baseUrl = `https://${req.headers.host}/api`;
      const loader = generateLoader(baseUrl, buildId);

      return res.status(200).json({
        buildId,
        loader,
        stage2: obfuscated,
        expiresAt: Math.floor(Date.now() / 1000) + ttl,
        hwidLocked: !!hwid,
      });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // --- GET ?action=stage2 — fetched at runtime by the loader ---
  if (req.method === 'GET' && action === 'stage2') {
    const buildId = url.searchParams.get('build');
    const hwid = url.searchParams.get('hw') || '';
    if (!buildId) return res.status(400).send('-- missing build');

    const raw = await kvGet(`build:${buildId}`);
    if (!raw) return res.status(404).send('-- expired');

    const build = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (build.hwidLock && build.hwidLock !== hwid) return res.status(200).send(dummyStage2());
    return res.status(200).send(build.obfuscated);
  }

  // --- GET / → UI ---
  if (req.method === 'GET' && !action) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(HTML);
  }

  return res.status(404).json({ error: 'not found' });
}

// ============================================================
// UTILS
// ============================================================
function readJSON(req) {
  return new Promise((resolve) => {
    if (req.body) return resolve(typeof req.body === 'string' ? JSON.parse(req.body) : req.body);
    let buf = '';
    req.on('data', c => buf += c);
    req.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve({}); } });
  });
}