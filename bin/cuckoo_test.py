#!/usr/bin/env python3
"""
Test Cuckoo API connectivity and functionality
"""

import requests
import sys

def test_cuckoo_api(host="127.0.0.1", port="8090"):
    """Comprehensive Cuckoo API test"""
    
    base_url = f"http://{host}:{port}"
    
    print(f"Testing Cuckoo API at {base_url}")
    print("=" * 60)
    
    # Test 1: Basic connectivity
    try:
        response = requests.get(base_url, timeout=10)
        print(f"[1] Basic connectivity: HTTP {response.status_code}")
        if response.status_code == 200:
            print("   ✓ API root accessible")
        else:
            print(f"   ✗ Unexpected response: {response.text[:100]}")
    except requests.exceptions.ConnectionError:
        print("   ✗ Cannot connect to API")
        return False
    
    # Test 2: Check available endpoints
    endpoints = [
        "/tasks",
        "/machines", 
        "/cuckoo",
        "/files"
    ]
    
    for endpoint in endpoints:
        try:
            url = base_url + endpoint
            response = requests.get(url, timeout=5)
            print(f"[2] {endpoint}: HTTP {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    print(f"   ✓ API working ({len(data)} keys)")
                else:
                    print(f"   ✓ API working ({len(data)} items)")
            elif response.status_code == 500:
                print("   ✗ Server error (check Cuckoo logs)")
            else:
                print(f"   ? Unexpected: {response.text[:50]}")
        except Exception as e:
            print(f"   ✗ Error: {str(e)}")
    
    # Test 3: Submit a test file (optional)
    print("\n[3] Testing file submission...")
    test_file = "/etc/hosts"  # Safe test file
    
    try:
        with open(test_file, 'rb') as f:
            files = {'file': ('test.txt', f)}
            response = requests.post(f"{base_url}/tasks/create/file", 
                                   files=files, timeout=30)
            print(f"   Submission: HTTP {response.status_code}")
            
            if response.status_code == 200:
                task_id = response.json().get('task_id')
                print(f"   ✓ Task created: ID {task_id}")
                return True
            else:
                print(f"   ✗ Failed: {response.text[:100]}")
    except Exception as e:
        print(f"   ✗ Exception: {str(e)}")
    
    return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "8090"
    
    success = test_cuckoo_api(host, port)
    sys.exit(0 if success else 1)
