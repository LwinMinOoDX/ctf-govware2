#!/usr/bin/env python3
"""
Test script for Flask-Limiter implementation with one-minute IP banning
Tests the rate limit of 5 requests per minute per IP
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor

def test_rate_limit():
    """Test the rate limiting functionality"""
    url = "http://localhost:5002/"
    
    print("Testing Flask-Limiter with 5 requests per minute limit...")
    print("=" * 60)
    
    # Test 1: Send 6 requests quickly to trigger rate limit
    print("Test 1: Sending 6 requests quickly to trigger rate limit")
    
    results = []
    
    def make_request(request_num):
        try:
            response = requests.get(url, timeout=10)
            return {
                'request': request_num,
                'status': response.status_code,
                'content_length': len(response.text),
                'has_banner': 'You\'re Banned for 1 Minute!' in response.text
            }
        except Exception as e:
            return {
                'request': request_num,
                'status': 'ERROR',
                'error': str(e),
                'has_banner': False
            }
    
    # Send 6 requests simultaneously
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(make_request, i+1) for i in range(6)]
        results = [future.result() for future in futures]
    
    # Analyze results
    success_count = sum(1 for r in results if r['status'] == 200)
    rate_limited_count = sum(1 for r in results if r['status'] == 429)
    banner_count = sum(1 for r in results if r.get('has_banner', False))
    
    print(f"Results:")
    for result in results:
        status = result['status']
        banner = " (with banner)" if result.get('has_banner', False) else ""
        print(f"  Request {result['request']}: {status}{banner}")
    
    print(f"\nSummary:")
    print(f"  Successful requests (200): {success_count}")
    print(f"  Rate limited requests (429): {rate_limited_count}")
    print(f"  Requests with ban banner: {banner_count}")
    
    # Verify expected behavior
    if success_count <= 5 and rate_limited_count >= 1:
        print("✅ Rate limiting is working correctly!")
    else:
        print("❌ Rate limiting may not be working as expected")
    
    if banner_count > 0:
        print("✅ Ban banner is displaying correctly!")
    else:
        print("❌ Ban banner is not displaying")
    
    print("\n" + "=" * 60)
    print("Test 2: Waiting 65 seconds to test IP unban...")
    print("This will test if the IP gets unbanned after 1 minute")
    
    # Wait 65 seconds (a bit more than 1 minute to be safe)
    for i in range(65, 0, -1):
        print(f"\rWaiting... {i} seconds remaining", end="", flush=True)
        time.sleep(1)
    
    print("\n\nTest 2: Testing access after waiting period")
    
    # Test access after waiting
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print("✅ IP successfully unbanned after 1 minute!")
            print(f"  Status: {response.status_code}")
        else:
            print(f"❌ Unexpected status after waiting: {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing after waiting: {e}")
    
    print("\n" + "=" * 60)
    print("Flask-Limiter test completed!")

if __name__ == "__main__":
    test_rate_limit()