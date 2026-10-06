import argparse
import getpass
import ipaddress
import json
import os
import secrets
import shutil
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from .store import Store, digest
from .system import identifier, private_write, keypair, run
from .network import repair, node_config
from .labs import Labs, load, policy, apply_policy


def parser():
    p=argparse.ArgumentParser(description='LabLink: private cybersecurity lab management')
    p.add_argument('--data-dir',default='/var/lib/lablink')
    sub=p.add_subparsers(dest='command',required=True)
    i=sub.add_parser('init'); i.add_argument('--subnet',default='10.1.2.0/24')
    i.add_argument('--hub-ip',default='10.1.2.11'); i.add_argument('--endpoint',required=True)
    i.add_argument('--registration-url',required=True); i.add_argument('--tls-cert',required=True)
    i.add_argument('--tls-key',required=True); i.add_argument('--interface',default='wg0')
    i.add_argument('--port',type=int,default=51820)
    s=sub.add_parser('serve'); s.add_argument('--bind',default='0.0.0.0'); s.add_argument('--port',type=int,default=8787)
    j=sub.add_parser('join'); j.add_argument('--hub-url'); j.add_argument('--invite'); j.add_argument('--ca-cert')
    j.add_argument('--name',default=socket.gethostname()); j.add_argument('--wait',action='store_true')
    j.add_argument('--fresh',action='store_true'); j.add_argument('--timeout',type=int,default=600)
    for name in ('status','nodes','audit','check'): sub.add_parser(name)
    for name in ('approve','revoke'):
        s=sub.add_parser(name); s.add_argument('request_id'); s.add_argument('--apply',action='store_true')
    i=sub.add_parser('invite'); i.add_argument('--expires',default='2h')
    r=sub.add_parser('repair'); r.add_argument('--apply',action='store_true')
    u=sub.add_parser('up'); g=u.add_mutually_exclusive_group(required=True)
    g.add_argument('--template'); g.add_argument('--topology'); u.add_argument('--apply-policy',action='store_true')
    for name in ('down','dashboard','policy','snapshot','reset','capture'):
        s=sub.add_parser(name); s.add_argument('--lab',required=True)
        if name=='dashboard': s.add_argument('--watch',action='store_true')
        if name=='policy': s.add_argument('--apply',action='store_true')
        if name=='snapshot': s.add_argument('--name',required=True)
        if name=='reset': s.add_argument('--snapshot',required=True)
        if name=='capture':
            s.add_argument('zone'); s.add_argument('--output',default='capture.pcap')
            s.add_argument('--interface'); s.add_argument('--wireshark',action='store_true'); s.add_argument('--zeek',action='store_true')
    s=sub.add_parser('protect'); s.add_argument('--hub',action='store_true'); s.add_argument('--lab'); s.add_argument('--enable',action='store_true')
    return p


def lifetime(value):
    import re
    m=re.fullmatch(r'([1-9][0-9]*)(s|m|h|d)',value)
    if not m: raise ValueError('Use a lifetime such as 30m or 2h')
    return int(m[1])*{'s':1,'m':60,'h':3600,'d':86400}[m[2]]


def initialize(a, store):
    subnet=ipaddress.ip_network(a.subnet)
    hub=ipaddress.ip_address(a.hub_ip)
    if subnet.version!=4 or not subnet.is_private or hub not in subnet.hosts():
        raise ValueError('Choose a private IPv4 subnet and usable hub address')
    identifier(a.interface)
    if not 1<=a.port<=65535: raise ValueError('Invalid listening port')
    url=urlparse(a.registration_url)
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Use an HTTPS registration URL without credentials or query parameters')
    cert=Path(a.tls_cert).resolve(); key=Path(a.tls_key).resolve()
    import ssl
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert,key)
    os.chmod(key,0o600)
    private,public=keypair(); token=secrets.token_urlsafe(32)
    store.initialize({'subnet':str(subnet),'hub_ip':str(hub),'endpoint':a.endpoint,
                      'registration_url':a.registration_url.rstrip('/'),'tls_cert':str(cert),
                      'tls_key':str(key),'interface':a.interface,'port':a.port,
                      'private_key':private,'public_key':public,'token_hash':digest(token)})
    repair(store)
    print('Hub initialized. Enrollment token (save securely): '+token)
    print('Generated '+str(store.directory/(a.interface+'.conf')))
    print('Install the generated tunnel under /etc/wireguard and start wg-quick explicitly; see docs/SETUP.md.')


def join(a, directory):
    from .api import request
    directory=Path(directory); local=directory/'enrollment.json'
    if a.fresh:
        local.unlink(missing_ok=True)
    if local.exists():
        state=json.loads(local.read_text())
    else:
        hub=a.hub_url; token=None
        if a.invite:
            u=urlparse(a.invite)
            if u.scheme!='lablink' or u.netloc!='join': raise ValueError('Invalid invite URI')
            q=parse_qs(u.query); hub=q['hub'][0]; token=q['token'][0]
        if not hub: raise ValueError('Choose --hub-url or --invite')
        identifier(a.name)
        if token is None: token=getpass.getpass('Enrollment token: ')
        private,public=keypair()
        result=request(hub.rstrip('/')+'/register',{'name':a.name,'public_key':public,'token':token},a.ca_cert)
        state={'hub':hub.rstrip('/'),'private_key':private,'request_id':result['request_id'],
               'poll_token':result['poll_token']}
        private_write(local,json.dumps(state))
    deadline=time.monotonic()+a.timeout
    print('Enrollment request: '+state['request_id'])
    while True:
        result=request(state['hub']+'/poll',{'request_id':state['request_id'],'poll_token':state['poll_token']},a.ca_cert)
        if result['status']=='approved':
            target=directory/'wg0.conf'; private_write(target,node_config(state['private_key'],result))
            print('Approved. Tunnel saved to '+str(target)); return
        if result['status']=='revoked': raise ValueError('Node revoked; new enrollment requires --fresh and a new name')
        if not a.wait or time.monotonic()>=deadline:
            print('Pending approval. Run join again to poll.'); return
        time.sleep(2)


def checks(store):
    results={tool:bool(shutil.which(tool)) for tool in ('wg','wg-quick','docker','nft','tcpdump')}
    results['private_files']=all((p.stat().st_mode & 0o077)==0 for p in store.directory.rglob('*') if p.is_file())
    try:
        interface=store.config()['interface']; run(['wg','show',interface]); results['wireguard_active']=True
    except (ValueError,RuntimeError,FileNotFoundError): results['wireguard_active']=False
    print(json.dumps(results,indent=2))
    return results['wg'] and results['private_files'] and results['wireguard_active']


def main(argv=None):
    os.umask(0o077)
    a=parser().parse_args(argv)
    try:
        if a.command=='join': join(a,a.data_dir); return
        store=Store(a.data_dir); labs=Labs(a.data_dir); c=a.command
        if c=='init': initialize(a,store)
        elif c=='serve':
            from .api import serve
            serve(store,a.bind,a.port)
        elif c in ('nodes','status'): print(json.dumps(store.nodes(),indent=2))
        elif c=='audit': store.export_audit(); print((store.directory/'audit.jsonl').read_text())
        elif c=='invite':
            token=store.invite(lifetime(a.expires))
            print('lablink://join?'+urlencode({'hub':store.config()['registration_url'],'token':token}))
        elif c in ('approve','revoke'):
            store.transition(a.request_id,'approved' if c=='approve' else 'revoked')
            repair(store,a.apply)
            print('Persistent records/config updated.'+(' Live interface synchronized.' if a.apply else ' Run repair --apply to synchronize the live interface.'))
        elif c=='repair': repair(store,a.apply); print('Hub configuration rebuilt')
        elif c=='check':
            if not checks(store): raise SystemExit(1)
        elif c=='up':
            path=a.topology or Path(__file__).parent/'templates'/(identifier(a.template)+'.yaml')
            name=labs.up(path,a.apply_policy); print('Lab started: '+name)
        elif c=='down': run(labs.command(a.lab,'down')); print('Lab stopped')
        elif c=='dashboard':
            while True:
                print(run(labs.command(a.lab,'ps')))
                if not a.watch: break
                time.sleep(3)
        elif c=='policy':
            t=load(labs.directory(a.lab)/'topology.yaml')
            if a.apply:
                apply_policy(t,labs.directory(a.lab)/'policy.nft')
                private_write(labs.directory(a.lab)/'policy-applied','true\n')
            else: print(policy(t))
        elif c=='snapshot': print(labs.snapshot(a.lab,a.name))
        elif c=='reset': labs.reset(a.lab,a.snapshot); print('Containers restored from snapshot')
        elif c=='capture': print(labs.capture(a.lab,a.zone,a.output,a.interface,a.wireshark,a.zeek))
        elif c=='protect':
            from .protect import protect
            print('\n'.join(protect(store,a.hub,a.lab,a.enable)))
        if c in ('up','down','snapshot','reset','capture','protect','policy','repair'):
            with store.connect() as db: store.event(db,c,lab=getattr(a,'lab',None))
            store.export_audit()
    except KeyboardInterrupt: pass
    except (ValueError,RuntimeError,FileNotFoundError,KeyError,OSError) as exc:
        print('LabLink: '+str(exc),file=sys.stderr); raise SystemExit(2)

if __name__=='__main__': main()
