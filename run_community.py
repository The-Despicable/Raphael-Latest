#!/usr/bin/env python3
"""Run the community multi-model brainstorming mode on the Orion exploit problem."""
import asyncio, sys, json, os
sys.path.insert(0, os.path.dirname(__file__))

from orchestrator.modes.community import handle

QUESTION = f"""
We have pre-auth RCE in CraftCMS 5.6.16 (CVE-2025-32432) against target Orion (10.129.54.86, nginx/1.18.0, PHP 8.2.30). The Yii2 DI container allows instantiating arbitrary classes via `handle[class]` + `handle[__construct()][N][...]` syntax on the `/index.php?p=actions/assets/generate-transform` endpoint.

What WORKS today:
1. FnStream destructor: `($this->_fn_close)()` calls zero-arg callables. Confirmed working for `phpinfo()`.
2. PhpManager `require()`: `yii\\rbac\\PhpManager` with `itemFile` path triggers `require(path)` in constructor. Confirmed path injection works.
3. CSRF: Cookie-based `CRAFT_CSRF_TOKEN` validation works without session_start.
4. PHP info confirmed: disable_functions=none, open_basedir=none, log_errors=On, error_log=/var/www/html/craft/storage/logs/phperrors.log, allow_url_fopen=On, allow_url_include=Off.
5. PhpManager require() error IS logged to error_log (PHP log_errors catches E_COMPILE_ERROR before converting to \Error).

What DOESN'T work:
1. FnStream receives 0 args — can't call system()/exec()/shell_exec() which need command string arg.
2. FileCookieJar writes JSON cookies — tried webroot paths, file not created (permissions or path wrong).
3. Session upload progress race — nginx fastcgi_request_buffering blocks partial body visibility.
4. data:// wrapper — allow_url_include=Off, require() fails.
5. php://filter base64-encode — output is ob_clean'd before 500 error page renders.

CURRENT ATTEMPT — Error log injection:
Step 1: POST with PhpManager(itemFile='/nonexistent/<?php file_put_contents(shell_path, code); ?>') → require() fails → error logged to error_log with <?php ... ?> in the path.
Step 2: POST with PhpManager(itemFile='/var/www/html/craft/storage/logs/phperrors.log') → require() includes error_log → <?php code executes → writes web shell.

ISSUE: Step 1 works (500 error), Step 2 works (500 error), but the shell file is NOT created at webroot. This means either:
  a) The error_log doesn't actually contain our payload (PHP's error handler doesn't log require() failures even with log_errors=On)
  b) The error_log contains our payload but PHP within the log doesn't execute (maybe too much garbage before/after?)
  c) file_put_contents fails (permissions)
  d) The path is wrong

QUESTION: How should we proceed? Brainstorm all possible approaches to get RCE or file read, including:
- What PHP functions can FnStream call with 0 args that lead to RCE?
- Other classes besides FnStream/PhpManager/FileCookieJar that have useful destructors?
- How to verify if error_log injection actually works?
- Alternative file write gadgets in PHP 8.2.30 / Yii2 / Guzzle?
- php://filter techniques for LFI?
- Upload progress tricks without race condition?
- Other paths to leverage the DI override?
"""

async def main():
    print("[*] Starting community brainstorming...", flush=True)
    result = await handle(QUESTION, rounds=2, temperature=0.85)
    
    print("\n" + "="*80)
    print("FINAL SYNTHESIS:")
    print("="*80)
    print(result.get("final", "No synthesis"))
    
    print("\n\nCONTRIBUTIONS:")
    for model, text in result.get("contributions", {}).items():
        print(f"\n{'='*60}")
        print(f"MODEL: {model}")
        print(f"{'='*60}")
        print(text[:2000])

if __name__ == "__main__":
    asyncio.run(main())
