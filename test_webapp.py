from fastapi.testclient import TestClient
from webapp import app
import pytest
import httpx
from unittest.mock import patch
import string

client = TestClient(app)

def test_health_check():
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}

def test_hash_text():
    response = client.post('/api/hash', json={'text': 'test'})
    assert response.status_code == 200
    assert response.json()['hash'] == '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'

def test_dns_lookup_success():
    with patch('httpx.get', return_value=httpx.Response(200)):
        response = client.get('/api/dns?domain=example.com')
        assert response.status_code == 200
        assert response.json() == {'status': 'success', 'domain': 'example.com', 'status_code': 200}

def test_dns_lookup_failure():
    with patch('httpx.get', side_effect=httpx.RequestError('mock error')):
        response = client.get('/api/dns?domain=example.com')
        assert response.status_code == 500
        assert response.json() == {'detail': 'DNS lookup failed: mock error'}

def test_generate_password():
    response = client.get('/api/password?length=12')
    assert response.status_code == 200
    password = response.json()['password']
    assert len(password) == 12
    assert any(c in string.ascii_letters for c in password)
    assert any(c in string.digits for c in password)
    assert any(c in string.punctuation for c in password)
