import base64
import concurrent.futures
import json
import os
import pytest
from lablink.store import Store, digest
from lablink.network import render_hub, node_config


def key(n): return base64.b64encode(bytes([n])*32).decode()

@pytest.fixture
def store(tmp_path):
    s=Store(tmp_path/'hub')
    s.initialize({'subnet':'10.1.2.0/24','hub_ip':'10.1.2.11','token_hash':digest('secret'),
                  'private_key':'PRIVATE','public_key':key(1),'endpoint':'192.168.1.26:51820',
                  'port':51820,'interface':'wg0','registration_url':'https://hub.test:8787'})
    return s


def test_approval_and_config(store):
    r=store.register('kali',key(2),'secret')
    assert store.poll(r['request_id'],r['poll_token'])['status']=='pending'
    assert key(2) not in render_hub(store)
    store.transition(r['request_id'],'approved')
    assert key(2) in render_hub(store)
    result=store.poll(r['request_id'],r['poll_token'])
    assert 'AllowedIPs = 10.1.2.0/24' in node_config('private',result)


def test_invite_one_use(store):
    t=store.invite(30); store.register('one',key(3),t)
    with pytest.raises(ValueError): store.register('two',key(4),t)


def test_concurrent_invite_consumption(store):
    token=store.invite(30)
    def attempt(i):
        try: return store.register('node'+str(i),key(i),token)
        except ValueError: return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(attempt,range(2,6)))
    assert sum(r is not None for r in results)==1


def test_revocation_blocks_reenrollment(store):
    r=store.register('node',key(2),'secret'); store.transition(r['request_id'],'approved')
    store.transition(r['request_id'],'revoked')
    assert key(2) not in render_hub(store)
    with pytest.raises(ValueError): store.register('other',key(2),'secret')
    with pytest.raises(ValueError): store.transition(r['request_id'],'approved')


def test_wrong_credentials(store):
    with pytest.raises(ValueError): store.register('node',key(2),'bad')
    r=store.register('node',key(2),'secret')
    with pytest.raises(ValueError): store.poll(r['request_id'],'bad')


def test_expired_invite(store):
    t=store.invite(30)
    with store.connect() as c: c.execute('UPDATE invites SET expires=0')
    with pytest.raises(ValueError): store.register('node',key(2),t)


def test_no_secrets_in_audit(store):
    r=store.register('node',key(2),'secret')
    audit=(store.directory/'audit.jsonl').read_text()
    assert 'PRIVATE' not in audit and 'secret' not in audit and r['poll_token'] not in audit
    assert all((p.stat().st_mode & 0o077)==0 for p in store.directory.iterdir() if p.is_file())

@pytest.mark.parametrize('name,keyvalue',[('../evil',key(2)),('node','bad'),('node',key(2)+'!')])
def test_invalid_registration(store,name,keyvalue):
    with pytest.raises(ValueError): store.register(name,keyvalue,'secret')


def test_concurrent_ip_allocation(store):
    def add(i): return store.register('node'+str(i),key(i),'secret')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(add,range(2,10)))
    ips=[n['ip'] for n in store.nodes()]
    assert len(set(ips))==8 and '10.1.2.11' not in ips
