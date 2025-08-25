<?php
declare(strict_types=1);

/*
  UNIQUE LINK REDIRECTOR — hardened, single file (no Turnstile)

  You get:
    - /new?key=ADMIN_KEY&u=https://final&ttl=600&max=2 → mints a unique link
    - /?c=CODE → JS gate (cookie + delay) + Proof-of-Work
    - Proof verified + POST consumption → 302 to final URL
    - HEAD/no-JS scanners get 200 "ok" and never burn tokens

  Azure App Settings (Portal → App Service → Configuration → Application settings)
    ADMIN_KEY       = long random (required)
    HOLD_MS         = 1200        (optional; 300–4000)
    TIE_IP          = 0 or 1      (optional; soft bind to first /24 after first pass)
    POW_DIFFICULTY  = 2           (0..4 hex zeros; start at 2)
    POW_BUCKET      = 60          (time bucket seconds, 30..300)
    REQUIRE_K       = 0 or 1      (optional; require ?k=K_VALUE on link)
    K_VALUE         = k1          (only if REQUIRE_K=1)
    REQUIRE_TS      = 0 or 1      (optional; require ?ts=<unix> within TS_WINDOW)
    TS_WINDOW       = 300         (validity window in seconds; 60..1800)
*/

session_name('r'); session_start();

/* ---------- Config ---------- */
$ADMIN_KEY = getenv('ADMIN_KEY') ?: '';
$HOLD_MS   = max(300, min(4000, (int)(getenv('HOLD_MS') ?: 1200)));
$TIE_IP    = (getenv('TIE_IP') === '1');

$POW_DIFF   = max(0, min(4, (int)(getenv('POW_DIFFICULTY') ?: 2)));
$POW_BUCKET = max(30, min(300, (int)(getenv('POW_BUCKET') ?: 60)));

$REQUIRE_K  = (getenv('REQUIRE_K') === '1');
$K_VALUE    = getenv('K_VALUE') ?: 'k1';
$REQUIRE_TS = (getenv('REQUIRE_TS') === '1');
$TS_WINDOW  = max(60, min(1800, (int)(getenv('TS_WINDOW') ?: 300)));

$COOKIE    = 'js_gate_ok';              // challenge cookie
$DATA_DIR  = __DIR__ . '/.data';
$DB_FILE   = $DATA_DIR . '/tokens.json';

$UA      = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$METHOD  = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$ACCEPT  = strtolower($_SERVER['HTTP_ACCEPT'] ?? '');
$IS_HEAD = ($METHOD === 'HEAD');
$IS_BOT  = (bool)preg_match('/(bot|spider|crawler|curl|wget|headless|selenium|phantom|monitor|uptime|httpclient)/i', $UA)
           || ($ACCEPT !== '' && strpos($ACCEPT, 'text/html') === false);
$IS_HEAD_OR_BOT = $IS_HEAD || $IS_BOT;

/* ---------- Tiny JSON "DB" ---------- */
function db_load(string $file, string $dir): array {
  if (!is_dir($dir)) @mkdir($dir, 0775, true);
  if (!is_file($file)) file_put_contents($file, json_encode(new stdClass()), LOCK_EX);
  $raw = file_get_contents($file);
  $db  = json_decode($raw ?: '{}', true);
  return is_array($db) ? $db : [];
}
function db_save(string $file, array $db): void {
  file_put_contents($file, json_encode($db, JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function db_prune(array &$db): void {
  $now = time();
  foreach ($db as $code => $row) {
    if (($row['exp'] ?? 0) < $now) unset($db[$code]);
  }
}

/* ---------- Helpers ---------- */
function code8(): string {
  return substr(strtoupper(rtrim(strtr(base64_encode(random_bytes(6)), '+/', '-_'), '=')), 0, 8);
}
function ip_prefix(string $ip): string {
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return substr($ip, 0, 7);
  $p = explode('.', $ip); return count($p) >= 3 ? ($p[0].'.'.$p[1].'.'.$p[2]) : $ip;
}
function ok_text(string $msg='ok'): void {
  header('Content-Type: text/plain; charset=utf-8');
  header('Cache-Control: no-store');
  echo $msg; exit;
}
function bad(string $msg, int $code=400): void {
  http_response_code($code);
  header('Content-Type: text/plain; charset=utf-8');
  echo $msg; exit;
}

/* ---------- Routing ---------- */
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if (isset($_GET['new'])) { $path = '/new'; }   // <-- make ?new=1 hit the /new route


/* Root w/o params: quick alive */
if ($path === '/' && !isset($_GET['c']) && !isset($_GET['go']) && !isset($_GET['new'])) {
  ok_text('ok');
}
if ($ADMIN_KEY === '') bad('Server not configured: missing ADMIN_KEY', 500);

/* Mint:
   /new?key=ADMIN_KEY&u=https://...&ttl=600&max=2
   (auto-adds &k=K_VALUE and &ts=now if enabled)
*/
if ($path === '/new') {
  if (($_GET['key'] ?? '') !== $ADMIN_KEY) bad('unauthorized', 401);
  $u   = trim((string)($_GET['u'] ?? ''));
  $ttl = max(30, min(3600, (int)($_GET['ttl'] ?? 600)));
  $max = max(1,  min(50,   (int)($_GET['max'] ?? 2)));

  if ($u === '') bad('missing u', 400);
  $parts = @parse_url($u);
  if (!$parts || !isset($parts['scheme']) || !isset($parts['host']) || strtolower($parts['scheme']) !== 'https') {
    bad('destination must be HTTPS', 400);
  }

  $db = db_load($DB_FILE, $DATA_DIR);
  db_prune($db);

  do { $code = code8(); } while (isset($db[$code]));

  $db[$code] = [
    'u'    => $u,
    'exp'  => time() + $ttl,
    'max'  => $max,
    'used' => 0,
    'ip'   => null,                      // filled on first successful consume if TIE_IP=1
    'chal' => bin2hex(random_bytes(8)),  // PoW challenge seed
  ];
  db_save($DB_FILE, $db);

  $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
  $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';

  $params = ['c' => $code];
  if ($REQUIRE_K)  $params['k']  = $K_VALUE;
  if ($REQUIRE_TS) $params['ts'] = (string)time();

  $link = $scheme.$host.'/?'.http_build_query($params);

  header('Content-Type: text/plain; charset=utf-8');
  header('X-Token', $code);
  echo "Use this link:\n$link\n\nJSON:\n";
  echo json_encode(['link'=>$link, 'code'=>$code, 'exp'=>$db[$code]['exp'], 'max'=>$max], JSON_UNESCAPED_SLASHES);
  exit;
}

/* POST consume handler — only POST actually spends a token */
if ($METHOD === 'POST' && isset($_POST['c'])) {
  $code = strtoupper(trim((string)$_POST['c']));
  $csrf = (string)($_POST['csrf'] ?? '');
  if (!hash_equals((string)($_SESSION['csrf'] ?? ''), $csrf)) bad('bad csrf', 403);

  $db  = db_load($DB_FILE, $DATA_DIR);
  $row = $db[$code] ?? null;
  if (!$row) bad('Not found', 404);
  if (($row['exp'] ?? 0) < time()) { unset($db[$code]); db_save($DB_FILE, $db); bad('Expired', 410); }

  // Re-check that gate was passed (cookie set in prior step)
  if (($_COOKIE['js_gate_ok'] ?? '') !== '1') bad('no gate', 403);

  // Verify pre-shared key / timestamp window if enabled (stored from GET in session)
  if ($REQUIRE_K  && empty($_SESSION['k_ok']))  bad('Not found', 404);
  if ($REQUIRE_TS && empty($_SESSION['ts_ok'])) bad('Expired', 410);

  // Verify PoW from hidden fields
  $p  = strtolower((string)($_POST['p']  ?? ''));
  $n  = (string)($_POST['n']  ?? '');
  $tb = (int)($_POST['tb'] ?? 0);
  $nowtb = intdiv(time(), $POW_BUCKET);

  // Adaptive difficulty (harder for suspicious UA)
  $effDiff = $POW_DIFF + ($IS_BOT ? 1 : 0);
  if ($effDiff > 4) $effDiff = 4;

  if ($effDiff > 0) {
    if ($tb <= 0 || abs($tb - $nowtb) > 1) bad('Proof expired', 410);
    $msg  = $row['chal'].'|'.$code.'|'.$tb.'|'.$n;
    $hash = hash('sha256', $msg);
    if (substr($hash, 0, $effDiff) !== str_repeat('0', $effDiff) || !hash_equals($hash, $p)) {
      bad('Proof invalid', 403);
    }
  }

  // Optional IP pinning
  if ($TIE_IP) {
    $ip   = $_SERVER['REMOTE_ADDR'] ?? '';
    $pref = ip_prefix($ip);
    if ($row['ip'] === null) { $row['ip'] = $pref; }
    elseif ($row['ip'] !== $pref) bad('Not allowed', 403);
  }

  // Consume usage and redirect
  $row['used'] = (int)($row['used'] ?? 0) + 1;
  if ($row['used'] >= (int)$row['max']) {
    unset($db[$code]);
  } else {
    $db[$code] = $row;
  }
  db_save($DB_FILE, $db);

  header('Location: ' . $row['u'], true, 302);
  exit;
}

/* GET consume — first pass with JS/PoW gate */
if (isset($_GET['c'])) {
  $code = strtoupper(trim((string)$_GET['c']));
  $db  = db_load($DB_FILE, $DATA_DIR);
  $row = $db[$code] ?? null;

  if (!$row) bad('Not found', 404);
  if (($row['exp'] ?? 0) < time()) { unset($db[$code]); db_save($DB_FILE, $db); bad('Expired', 410); }

  // Pre-shared key / timestamp checks (light)
  if ($REQUIRE_K) {
    $k = (string)($_GET['k'] ?? '');
    if ($k !== $K_VALUE) bad('Not found', 404);
    $_SESSION['k_ok'] = true;
  }
  if ($REQUIRE_TS) {
    $ts = (int)($_GET['ts'] ?? 0);
    if ($ts === 0 || abs(time() - $ts) > $TS_WINDOW) bad('Expired', 410);
    $_SESSION['ts_ok'] = true;
  }

  // Bots & HEAD: do not burn; give harmless OK
  if ($IS_HEAD_OR_BOT) ok_text('ok');

  // JS/cookie gate + PoW page
  header('Content-Type: text/html; charset=utf-8');
  header('Cache-Control: no-store');

  // adaptive difficulty (same logic as in POST)
  $effDiff = $POW_DIFF + ($IS_BOT ? 1 : 0);
  if ($effDiff > 4) $effDiff = 4;

  $chal  = htmlspecialchars($row['chal'], ENT_QUOTES);
  $codeH = htmlspecialchars($code, ENT_QUOTES);
  $csrf  = bin2hex(random_bytes(16));
  $_SESSION['csrf'] = $csrf;
  ?>
  <!doctype html>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Just a moment…</title>
  <div style="font-family:system-ui;max-width:520px;margin:20vh auto;padding:24px;border:1px solid #ddd;border-radius:10px;line-height:1.55;text-align:center">
    <div>Preparing your redirect…</div>
    <div id="dots" aria-hidden="true" style="margin-top:8px;color:#666">.</div>
    <noscript>
      <p style="color:#b00020;margin-top:12px">JavaScript required.</p>
    </noscript>
  </div>
  <form id="go" method="post" action="./" style="display:none">
    <input type="hidden" name="c" value="<?=$codeH?>">
    <input type="hidden" name="csrf" value="<?=htmlspecialchars($csrf, ENT_QUOTES)?>">
    <input type="hidden" name="p" value="">
    <input type="hidden" name="n" value="">
    <input type="hidden" name="tb" value="">
  </form>
  <script>
    // tiny dot animation
    (function(){var el=document.getElementById('dots'),n=0;setInterval(function(){n=(n+1)%4;el.textContent='.'.repeat(n+1);},300);})();
    // set cookie so non-JS scanners can't progress
    (function(){try{
      var expires=new Date(Date.now()+3600*1000).toUTCString();
      document.cookie="<?php echo $COOKIE; ?>=1; path=/; SameSite=Lax; expires="+expires;
    }catch(e){}})();
    // SHA-256 helper
    async function sha256Hex(s){
      const buf = new TextEncoder().encode(s);
      const h = await crypto.subtle.digest('SHA-256', buf);
      return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('');
    }
    // Proof-of-work: find nonce s.t. sha256(chal|code|tb|nonce) starts with N zeros
    (async function(){
      const chal = "<?=$chal?>";
      const code = "<?=$codeH?>";
      const diff = <?= (int)$effDiff ?>;
      const bucketSec = <?= (int)$POW_BUCKET ?>;
      const tb = Math.floor(Date.now()/1000 / bucketSec);
      const target = '0'.repeat(diff);
      let nonce = 0, hash = "";
      if (diff > 0) {
        do {
          hash = await sha256Hex(chal + '|' + code + '|' + tb + '|' + nonce);
          if (hash.substring(0, diff) === target) break;
          nonce++;
          if (nonce % 500 === 0) await new Promise(r=>setTimeout(r,0));
        } while(true);
      } else {
        hash = await sha256Hex(chal + '|' + code + '|' + tb + '|0'); nonce = 0;
      }
      setTimeout(function(){
        var f = document.getElementById('go');
        f.p.value = hash; f.n.value = String(nonce); f.tb.value = String(tb);
        f.submit(); // POST consumption (many scanners won't do this)
      }, <?= (int)$HOLD_MS ?>);
    })();
  </script>
  <?php
  exit;
}

/* Fallback */
ok_text('ok');
