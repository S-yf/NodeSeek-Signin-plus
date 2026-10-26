# -*- coding: utf-8 -*-
"""
浏览器登录模块：解决 nodeseek 登录接口的 FingerprintJS 设备指纹签名。

nodeseek 的 POST /api/account/signIn 除了需要 Turnstile 验证码 token 外，
还必须携带由前端浏览器生成的请求头：
  - x-integrity-token: FingerprintJS visitorId（基于真实浏览器指纹）
  - x-security-token: localStorage 中的 security_token
纯 Python(curl_cffi) 无法生成有效的 visitorId，因此本模块用真实浏览器
(Playwright + Chromium) 打开登录页，让前端自动生成全部签名，
同时把 YesCaptcha 解出的 Turnstile token 通过"假 turnstile"注入，
从而完成真实登录并返回 Cookie 字符串。

用法（在 nodeseek_sign.py 的 session_login 中，Cookie 失效时调用）:
    from browser_login import browser_login
    cookie = browser_login(user, password, client_key, api_base_url)
"""
import os
import sys
import json

SITEKEY = "0x4AAAAAAAaNy7leGjewpVyR"
LOGIN_URL = "https://www.nodeseek.com/signIn.html"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")

# 假 turnstile：让前端"请完成Cloudflare人机验证"不再拦截。
# render 被调用时，轮询等待 window.__YC_TOKEN__ 就绪后回调给 Vue 组件，
# 使 m.value 变成 YesCaptcha 解出的有效 token。
FAKE_TS_HOOK = r"""
(() => {
  if (window.__FAKE_TS__) return;
  window.__FAKE_TS__ = true;
  const makeTs = () => ({
    render: (el, opts) => {
      if (opts && typeof opts.callback === 'function') {
        const waitFor = () => {
          if (window.__YC_TOKEN__) { opts.callback(window.__YC_TOKEN__); }
          else { setTimeout(waitFor, 200); }
        };
        setTimeout(waitFor, 400);
      }
      return 'fake-widget-id';
    },
    getResponse: () => window.__YC_TOKEN__ || '',
    reset: () => {}, remove: () => {}, execute: () => {},
  });
  Object.defineProperty(window, 'turnstile', {
    configurable: true,
    get() { return makeTs(); },
    set() { /* 忽略真实 api.js 赋值 */ }
  });
})();
"""


def _get_captcha_token(client_key: str, api_base_url: str) -> str:
    """使用仓库自带的 YesCaptchaSolver 解决 Turnstile，返回 token。"""
    from yescaptcha import YesCaptchaSolver
    solver = YesCaptchaSolver(
        api_base_url=api_base_url or "https://api.yescaptcha.com",
        client_key=client_key,
        max_retries=30,
        retry_interval=3,
    )
    token = solver.solve(url=LOGIN_URL, sitekey=SITEKEY, verbose=False)
    if not token:
        print("[browser_login] YesCaptcha 获取 token 失败")
    else:
        print(f"[browser_login] YesCaptcha token 前12位: {token[:12]}")
    return token or ""


def browser_login(
    user: str,
    password: str,
    client_key: str,
    api_base_url: str = "",
    proxy: str = "",
    timeout_seconds: int = 120,
) -> str:
    """
    用 Playwright 真实浏览器完成 nodeseek 登录，返回 Cookie 字符串。
    失败返回空字符串。

    参数:
        user/password: nodeseek 账号
        client_key/api_base_url: YesCaptcha 密钥与节点（复用仓库 env）
        proxy: 可选 HTTP 代理（如 http://127.0.0.1:10808），CI 通常不需要
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[browser_login] 未安装 playwright，无法使用浏览器登录")
        return ""

    token = _get_captcha_token(client_key, api_base_url)
    if not token:
        return ""

    proxy_cfg = {"server": proxy} if proxy else None
    try:
        with sync_playwright() as p:
            # 优先使用真实 Chrome（TLS 指纹真实，Cloudflare 不易识别）；
            # 若系统无 Chrome 则回退 Playwright 自带 Chromium。
            chrome_args = [
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--window-size=1920,1080",
            ]
            try:
                browser = p.chromium.launch(
                    channel="chrome", headless=True, args=chrome_args
                )
            except Exception:
                browser = p.chromium.launch(
                    headless=True, args=chrome_args
                )
            ctx = browser.new_context(
                proxy=proxy_cfg,
                user_agent=UA,
                viewport={"width": 1920, "height": 1080},
            )
            # token 在页面最早阶段注入（add_init_script 先于所有页面脚本）
            ctx.add_init_script(
                "window.__YC_TOKEN__ = " + json.dumps(token) + ";\n" + FAKE_TS_HOOK
            )
            page = ctx.new_page()
            page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(5000)
            page.fill("#stacked-email", user)
            page.fill("#stacked-password", password)
            page.click('button:has-text("登录")')
            print("[browser_login] 已提交登录，等待跳转...")

            deadline = timeout_seconds
            ok = False
            start = 0
            while start < deadline:
                page.wait_for_timeout(1000)
                start += 1
                # 判断是否真正登录成功：跳转到主页（不再停留在任何 signIn/emailSignIn 页）。
                # 必须大小写不敏感，否则 emailSignIn.html 会被误判为成功。
                if "signin" not in page.url.lower():
                    print(f"[browser_login] 已跳转离开登录页: {page.url}")
                    ok = True
                    break
                elif start % 10 == 0:
                    print(f"[browser_login] 仍在登录页({start}s): {page.url[:100]}")
            if not ok:
                print("[browser_login] 登录页未跳转，登录可能失败")
                try:
                    page.screenshot(path="ns_login_fail.png")
                except Exception:
                    pass
                browser.close()
                return ""

            page.wait_for_timeout(2000)
            cookies = ctx.cookies()
            browser.close()
            if not cookies:
                print("[browser_login] 未获取到 Cookie")
                return ""
            cookie = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            print(f"[browser_login] 获取到 Cookie，长度 {len(cookie)}")
            return cookie
    except Exception as e:
        print(f"[browser_login] 浏览器登录异常: {e}")
        return ""


if __name__ == "__main__":
    # 手动测试：从环境变量读取
    user = os.environ.get("USER1") or os.environ.get("USER")
    pwd = os.environ.get("PASS1") or os.environ.get("PASS")
    ck = os.environ.get("CLIENT_KEY")
    if not user or not pwd or not ck:
        print("[!] 需要 USER1/PASS1/CLIENT_KEY 环境变量")
        sys.exit(1)
    cookie = browser_login(
        user, pwd, ck,
        api_base_url=os.environ.get("API_BASE_URL", ""),
        proxy=os.environ.get("PROXY", ""),
    )
    if cookie:
        print(f"[OK] Cookie: {cookie[:50]}...")
        sys.exit(0)
    sys.exit(2)
