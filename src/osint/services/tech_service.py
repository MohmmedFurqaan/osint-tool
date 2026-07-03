import httpx
import re

async def detect_technologies_async(url: str) -> list:
    """
    Detect technologies by inspecting headers and HTML body.
    """
    detected = set()
    
    try:
        if not url.startswith('http'):
            url = f"http://{url}"
            
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url)
            headers = resp.headers
            body = resp.text.lower()
            
            # --- Header-based detection ---
            server = headers.get('server', '').lower()
            if 'nginx' in server:
                detected.add('Nginx')
            elif 'apache' in server:
                detected.add('Apache')
            elif 'cloudflare' in server:
                detected.add('Cloudflare')
            elif 'openresty' in server:
                detected.add('OpenResty')
            elif 'litespeed' in server:
                detected.add('LiteSpeed')
            elif 'iis' in server:
                detected.add('Microsoft IIS')
                
            x_powered_by = headers.get('x-powered-by', '').lower()
            if 'php' in x_powered_by:
                detected.add('PHP')
            elif 'express' in x_powered_by:
                detected.add('Express.js')
            elif 'asp.net' in x_powered_by:
                detected.add('ASP.NET')
            elif 'next.js' in x_powered_by:
                detected.add('Next.js')
                
            # --- Body-based detection (HTML) ---
            if 'wp-content' in body or 'wp-includes' in body:
                detected.add('WordPress')
            if 'ghost' in body and 'ghost.org' in body:
                detected.add('Ghost')
            if '<div id="___gatsby">' in body or 'gatsby-focus-wrapper' in body:
                detected.add('Gatsby')
            if '__next' in body or '_next/static' in body:
                detected.add('Next.js')
            if 'react' in body and ('data-reactroot' in body or 'react-dom' in body):
                detected.add('React')
            if 'vue' in body and ('data-v-' in body or 'vue-router' in body):
                detected.add('Vue.js')
            if 'ng-app' in body or 'ng-version' in body:
                detected.add('Angular')
            if 'shopify' in body:
                detected.add('Shopify')
            if 'bootstrap' in body:
                detected.add('Bootstrap')
            if 'tailwind' in body:
                detected.add('Tailwind CSS')
            if 'jquery' in body:
                detected.add('jQuery')
                
    except Exception:
        pass
        
    return sorted(list(detected))

