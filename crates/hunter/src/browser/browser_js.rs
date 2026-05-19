/// Generate a Playwright script for DOM analysis of a URL.
pub fn generate_dom_analysis_script(url: &str, output_file: &str) -> String {
    format!(r#"const {{ chromium }} = require('playwright');

(async () => {{
    const browser = await chromium.launch({{ headless: true }});
    const context = await browser.newContext({{
        userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Aegis/0.1'
    }});
    const page = await context.newPage();
    await page.goto('{url}', {{ waitUntil: 'networkidle', timeout: 30000 }});

    // Extract all forms
    const forms = await page.evaluate(() => {{
        return Array.from(document.forms).map(f => ({{
            action: f.action,
            method: f.method,
            inputs: Array.from(f.elements).map(e => {{ return {{ name: e.name, type: e.type, id: e.id }}; }})
        }}));
    }});

    // Extract all scripts
    const scripts = await page.evaluate(() => {{
        return Array.from(document.scripts).map(s => s.src).filter(s => s);
    }});

    // Extract all links and endpoints
    const links = await page.evaluate(() => {{
        return Array.from(document.querySelectorAll('a[href], link[href], area[href]'))
            .map(e => e.getAttribute('href'))
            .filter(h => h && (h.startsWith('/') || h.startsWith('http')));
    }});

    // Extract comments (may contain hidden endpoints)
    const comments = await page.evaluate(() => {{
        const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
        let comments = [];
        while (walker.nextNode()) {{
            comments.push(walker.currentNode.textContent.trim());
        }}
        return comments.filter(c => c);
    }});

    // Extract localStorage and sessionStorage keys
    const storage = await page.evaluate(() => {{
        return {{
            localStorage: Object.entries({{...localStorage}}).map(([k, v]) => `${{k}}: ${{v.substring(0, 100)}}`),
            sessionStorage: Object.entries({{...sessionStorage}}).map(([k, v]) => `${{k}}: ${{v.substring(0, 100)}}`),
        }};
    }});

    const result = {{
        url: '{url}',
        title: await page.title(),
        forms,
        scripts,
        links,
        comments,
        storage,
        cookies: await context.cookies(),
        html_length: (await page.content()).length,
    }};

    const fs = require('fs');
    fs.writeFileSync('{output_file}', JSON.stringify(result, null, 2));
    await browser.close();
    console.log('DOM analysis complete:', '{output_file}');
}})();
"#)
}

/// Generate a Playwright script for authenticated scanning.
pub fn generate_auth_scan_script(
    login_url: &str,
    username_selector: &str,
    password_selector: &str,
    username: &str,
    password: &str,
    targets: &[String],
    output_dir: &str,
) -> String {
    let targets_json = serde_json::to_string(targets).unwrap_or_default();

    format!(r#"const {{ chromium }} = require('playwright');

(async () => {{
    const browser = await chromium.launch({{ headless: true }});
    const context = await browser.newContext();
    const page = await context.newPage();

    // Login
    await page.goto('{login_url}', {{ waitUntil: 'networkidle', timeout: 30000 }});
    await page.fill('{username_selector}', '{username}');
    await page.fill('{password_selector}', '{password}');
    await page.click('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign in")');
    await page.waitForTimeout(3000);

    // Save authenticated state
    await context.storageState({{ path: '{output_dir}/auth-state.json' }});
    console.log('Authenticated, session saved');

    // Visit each target URL while authenticated
    const targets = {targets_json};
    const fs = require('fs');

    for (const target of targets) {{
        try {{
            await page.goto(target, {{ waitUntil: 'networkidle', timeout: 30000 }});
            const content = await page.content();
            const title = await page.title();
            const url = page.url();

            fs.writeFileSync(
                `{output_dir}/${{target.replace(/[^a-z0-9]/gi, '_')}}.html`,
                content
            );

            console.log(`Scanned: ${{url}} (${{content.length}} bytes)`);
        }} catch (e) {{
            console.error(`Failed: ${{target}}: ${{e.message}}`);
        }}
    }}

    await browser.close();
    console.log('Auth scan complete');
}})();
"#)
}

/// Generate a Playwright script for visual verification of a vulnerability.
pub fn generate_verification_script(
    url: &str,
    exploit_payload: &str,
    expected_indicator: &str,
    screenshot_path: &str,
) -> String {
    // Escape single quotes in the payload for JS string safety
    let safe_payload = exploit_payload.replace('\'', "\\'");

    format!(r#"const {{ chromium }} = require('playwright');
const fs = require('fs');

(async () => {{
    const browser = await chromium.launch({{ headless: true }});
    const page = await browser.newPage();

    // Listen for dialog (alert/confirm/prompt) for XSS detection
    page.on('dialog', dialog => {{
        console.log('Dialog detected:', dialog.type(), dialog.message());
        const result = {{ dialog_type: dialog.type(), message: dialog.message() }};
        fs.writeFileSync('{screenshot_path}.dialog.json', JSON.stringify(result));
        dialog.accept();
    }});

    await page.goto('{url}', {{ waitUntil: 'networkidle', timeout: 30000 }});

    // Inject exploit if needed
    if ('{safe_payload}') {{
        await page.evaluate('{safe_payload}');
    }}

    await page.waitForTimeout(2000);

    // Take screenshot
    await page.screenshot({{ path: '{screenshot_path}.png', fullPage: true }});

    // Check for expected indicator
    const content = await page.content();
    const hasIndicator = content.includes('{expected_indicator}');
    console.log(`Vulnerability verified: ${{hasIndicator}}`);

    const result = {{
        url: '{url}',
        title: await page.title(),
        indicator_found: hasIndicator,
        content_length: content.length,
    }};
    fs.writeFileSync('{screenshot_path}.json', JSON.stringify(result));

    await browser.close();
}})();
"#)
}

/// Available browser automation profiles.
pub fn browser_profiles() -> Vec<&'static str> {
    vec![
        "chrome-desktop", "chrome-mobile", "firefox-desktop", "safari-iphone",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dom_script() {
        let script = generate_dom_analysis_script("https://example.com", "/tmp/dom.json");
        assert!(script.contains("chromium.launch"));
        assert!(script.contains("example.com"));
        assert!(script.contains("document.forms"));
        assert!(script.contains("localStorage"));
    }

    #[test]
    fn test_generate_auth_script() {
        let script = generate_auth_scan_script(
            "https://target.com/login", "#username", "#password",
            "admin", "secret", &[], "/tmp/auth",
        );
        assert!(script.contains("page.fill"));
        assert!(script.contains("storageState"));
    }

    #[test]
    fn test_generate_verification_script() {
        let script = generate_verification_script(
            "https://target.com/page", "<script>alert(1)</script>",
            "alert(1)", "/tmp/screenshot",
        );
        assert!(script.contains("dialog"));
        assert!(script.contains("screenshot"));
    }

    #[test]
    fn test_browser_profiles() {
        let profiles = browser_profiles();
        assert!(profiles.contains(&"chrome-desktop"));
        assert!(profiles.contains(&"firefox-desktop"));
    }
}
