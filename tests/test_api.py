import base64
import json
import multiprocessing
import shutil
import socket
import ssl
import subprocess
import time
from urllib.error import URLError,HTTPError
import pytest
from lablink.api import request,serve
from lablink.store import Store,digest


def test_http_rejected():
    with pytest.raises(ValueError,match='HTTPS'): request('http://127.0.0.1/register',{})


@pytest.fixture
def tls_hub(tmp_path):
    if not shutil.which('openssl'): pytest.skip('openssl unavailable')
    cert=tmp_path/'hub.crt'; key=tmp_path/'hub.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                    '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost',
                    '-addext','subjectAltName=IP:127.0.0.1'],capture_output=True,check=True)
    store=Store(tmp_path/'hub')
    store.initialize({'subnet':'10.1.2.0/24','hub_ip':'10.1.2.11','token_hash':digest('secret'),
                      'private_key':'PRIVATE','public_key':base64.b64encode(bytes(32)).decode(),
                      'endpoint':'127.0.0.1:51820','tls_cert':str(cert),'tls_key':str(key)})
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    process=multiprocessing.Process(target=serve,args=(store,'127.0.0.1',port),daemon=True)
    process.start()
    url=f'https://127.0.0.1:{port}'
    for _ in range(100):
        try:
            request(url+'/poll',{},str(cert))
        except HTTPError: break
        except URLError: time.sleep(.02)
    else:
        process.terminate(); process.join(); pytest.fail('TLS server did not start')
    try: yield store,url,str(cert)
    finally: process.terminate(); process.join(timeout=3)


def test_tls_enrollment_roundtrip(tls_hub):
    store,url,cert=tls_hub
    r=request(url+'/register',{'name':'kali','public_key':base64.b64encode(bytes([1])*32).decode(),'token':'secret'},cert)
    assert request(url+'/poll',r,cert)['status']=='pending'
    store.transition(r['request_id'],'approved')
    assert request(url+'/poll',r,cert)['status']=='approved'
    store.transition(r['request_id'],'revoked')
    assert request(url+'/poll',r,cert)['status']=='revoked'


def test_untrusted_certificate_rejected(tls_hub):
    _,url,_=tls_hub
    with pytest.raises(URLError): request(url+'/poll',{})
