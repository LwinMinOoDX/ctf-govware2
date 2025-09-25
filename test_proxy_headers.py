#!/usr/bin/env python3
"""
Test script to verify Flask-Limiter works with proxy headers
for deployed platforms like Heroku, Railway, Render, etc.
"""

import requests
import time

def test_with_proxy_headers():
    """Test rate limiting with various proxy headers"""
    base_url = "http://localhost:5002"
    
    print("Testing Flask-Limiter with proxy headers...")
    print("=" * 60)
    
    # Test different proxy headers that deployment platforms use
    proxy_headers = [
        {'X-Forwarded-For': '192.168.1.100'},
        {'X-Real-IP': '192.168.1.101'},
        {'X-Client-IP': '192.168.1.102'},
        {'CF-Connecting-IP': '192.168.1.103'},
        {'True-Client-IP': '192.168.1.104'},
    ]
    
    for i, headers in enumerate(proxy_headers, 1):
        print(f"\nTest {i}: Testing with headers: {headers}")
        
        # Send 6 requests quickly to trigger rate limit
        responses = []
        for j in range(6):
            try:
                response = requests.get(f"{base_url}/login", headers=headers, timeout=5)
                responses.append(response.status_code)
                print(f"  Request {j+1}: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"  Request {j+1}: Error - {e}")
                responses.append(0)
        
        # Count successful and rate-limited requests
        success_count = responses.count(200)
        rate_limited_count = responses.count(429)
        
        print(f"  Results: {success_count} successful, {rate_limited_count} rate-limited")
        
        if rate_limited_count > 0:
            print(f"  ✅ Rate limiting working for IP: {list(headers.values())[0]}")
        else:
            print(f"  ❌ Rate limiting NOT working for IP: {list(headers.values())[0]}")
        
        # Wait a bit between tests
        time.sleep(2)

def test_x_forwarded_for_multiple_ips():
    """Test X-Forwarded-For with multiple IPs (common in proxy chains)"""
    print(f"\n{'='*60}")
    print("Testing X-Forwarded-For with multiple IPs...")
    
    base_url = "http://localhost:5002"
    
    # Simulate proxy chain with multiple IPs
    headers = {'X-Forwarded-For': '203.0.113.1, 198.51.100.1, 192.0.2.1'}
    
    print(f"Headers: {headers}")
    print("Should use first IP: 203.0.113.1")
    
    responses = []
    for i in range(6):
        try:
            response = requests.get(f"{base_url}/login", headers=headers, timeout=5)
            responses.append(response.status_code)
            print(f"  Request {i+1}: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"  Request {i+1}: Error - {e}")
            responses.append(0)
    
    success_count = responses.count(200)
    rate_limited_count = responses.count(429)
    
    print(f"Results: {success_count} successful, {rate_limited_count} rate-limited")
    
    if rate_limited_count > 0:
        print("✅ Rate limiting working with multiple IPs in X-Forwarded-For")
    else:
        print("❌ Rate limiting NOT working with multiple IPs in X-Forwarded-For")

def test_fallback_to_remote_addr():
    """Test fallback to REMOTE_ADDR when no proxy headers present"""
    print(f"\n{'='*60}")
    print("Testing fallback to REMOTE_ADDR (no proxy headers)...")
    
    base_url = "http://localhost:5002"
    
    # No proxy headers - should fall back to REMOTE_ADDR
    responses = []
    for i in range(6):
        try:
            response = requests.get(f"{base_url}/login", timeout=5)
            responses.append(response.status_code)
            print(f"  Request {i+1}: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"  Request {i+1}: Error - {e}")
            responses.append(0)
    
    success_count = responses.count(200)
    rate_limited_count = responses.count(429)
    
    print(f"Results: {success_count} successful, {rate_limited_count} rate-limited")
    
    if rate_limited_count > 0:
        print("✅ Rate limiting working with fallback to REMOTE_ADDR")
    else:
        print("❌ Rate limiting NOT working with fallback to REMOTE_ADDR")

if __name__ == "__main__":
    try:
        test_with_proxy_headers()
        test_x_forwarded_for_multiple_ips()
        test_fallback_to_remote_addr()
        
        print(f"\n{'='*60}")
        print("Proxy header testing completed!")
        print("\nIf rate limiting is working in these tests, it should work")
        print("on deployed platforms like Heroku, Railway, Render, etc.")
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"\nTest failed with error: {e}")