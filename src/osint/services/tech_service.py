def detect_technologies(headers: dict) -> list:
    """
    Very basic signature matching based on headers.
    In a real-world scenario, this would load signatures from data/signatures.json
    and inspect both headers and HTML body.
    """
    detected = []
    
    server = headers.get('server', '').lower()
    if 'nginx' in server:
        detected.append('Nginx')
    elif 'apache' in server:
        detected.append('Apache')
    elif 'cloudflare' in server:
        detected.append('Cloudflare')
        
    x_powered_by = headers.get('x-powered-by', '').lower()
    if 'php' in x_powered_by:
        detected.append('PHP')
    elif 'express' in x_powered_by:
        detected.append('Express.js')
    elif 'asp.net' in x_powered_by:
        detected.append('ASP.NET')
        
    return detected
