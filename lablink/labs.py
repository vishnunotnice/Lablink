"""Compose ranges, dedicated nftables tables, filesystem snapshots, capture."""
import copy
import ipaddress
import json
import subprocess
from pathlib import Path
import yaml
from .system import identifier, private_write, run


def load(path):
    t=yaml.safe_load(Path(path).read_text())
    identifier(t['name'])
    overall=ipaddress.ip_network(t['lab_subnet'])
    if overall.version!=4 or not overall.is_private:
        raise ValueError('Lab subnet must be private IPv4')
    zones=t['zones']
    networks=[]
    for name, zone in zones.items():
        identifier(name)
        net=ipaddress.ip_network(zone['cidr'])
        if not net.subnet_of(overall) or any(net.overlaps(n) for n in networks):
            raise ValueError('Zones must be nonoverlapping subnets within lab_subnet')
        networks.append(net)
    for name,s in t['services'].items():
        identifier(name)
        if not isinstance(s['image'],str) or not s['image']:
            raise ValueError('Service image required')
        if s['zone'] not in zones:
            raise ValueError('Unknown service zone')
        # One zone per service prevents a container bypassing policy by bridging zones.
        if set(s)-{'image','zone','command','environment'}:
            raise ValueError('Unsupported service fields (volumes, ports and privileges excluded)')
        if 'command' in s and not isinstance(s['command'],list):
            raise ValueError('command must be an argv list')
    for f in t.get('allowed_flows',[]):
        if f['from'] not in zones or f['to'] not in zones:
            raise ValueError('Unknown flow zone')
        if f.get('protocol','tcp') not in ('tcp','udp','icmp'):
            raise ValueError('Invalid protocol')
        ports=f.get('ports',[])
        if not isinstance(ports,list) or any(type(n)!=int or not 1<=n<=65535 for n in ports):
            raise ValueError('Invalid ports')
        if f.get('protocol')=='icmp' and ports:
            raise ValueError('ICMP does not use ports')
    return t


def compose(t):
    return {'services':{n:{'image':s['image'],'restart':'unless-stopped',
              'networks':[s['zone']],**{k:s[k] for k in ('command','environment') if k in s}}
              for n,s in t['services'].items()},
            'networks':{z:{'internal':True,'driver':'bridge','ipam':{'config':[{'subnet':v['cidr']}]}}
                        for z,v in t['zones'].items()}}


def policy(t):
    name='lablink_'+t['name'].replace('-','_')
    overall=t['lab_subnet']
    # This chain touches only packets whose source or destination belongs to this lab.
    lines=[f'table inet {name} {{',' chain forward {',
           '  type filter hook forward priority -10; policy accept;',
           f'  ip saddr {overall} ct state established,related accept',
           f'  ip daddr {overall} ct state established,related accept']
    for z in t['zones'].values():
        lines.append(f"  ip saddr {z['cidr']} ip daddr {z['cidr']} accept")
    for f in t.get('allowed_flows',[]):
        proto=f.get('protocol','tcp'); ports=f.get('ports',[])
        match='ip protocol icmp' if proto=='icmp' else f'ip protocol {proto}'
        if ports:
            match+=f" {proto} dport {{ "+', '.join(map(str,ports))+' }'
        lines.append(f"  ip saddr {t['zones'][f['from']]['cidr']} ip daddr {t['zones'][f['to']]['cidr']} {match} accept")
    lines += [f'  ip saddr {overall} drop',f'  ip daddr {overall} drop',' }',
              ' chain input {','  type filter hook input priority -10; policy accept;',
              f'  ip saddr {overall} drop',' }','}']
    return '\n'.join(lines)+'\n'


def apply_policy(t, path):
    name='lablink_'+t['name'].replace('-','_')
    # Replace this table only; never flush the host ruleset.
    listing=run(['nft','list','tables'])
    prefix=f'delete table inet {name}\n' if f'table inet {name}' in listing.splitlines() else ''
    text=prefix+policy(t)
    run(['nft','--check','-f','-'],input=text)
    run(['nft','-f','-'],input=text)
    private_write(path,policy(t))


class Labs:
    def __init__(self, directory):
        self.root=Path(directory)/'labs'
    def directory(self,name):
        return self.root/identifier(name)
    def command(self,name,*args):
        return ['docker','compose','--project-name','lablink-'+identifier(name),
                '-f',str(self.directory(name)/'compose.yaml'),*args]
    def up(self,path,apply=False):
        t=load(path); d=self.directory(t['name']); d.mkdir(parents=True,exist_ok=True,mode=0o700)
        private_write(d/'topology.yaml',yaml.safe_dump(t))
        private_write(d/'compose.yaml',yaml.safe_dump(compose(t)))
        private_write(d/'policy.nft',policy(t))
        run(self.command(t['name'],'config','--quiet'))
        if apply:
            apply_policy(t,d/'policy.nft')
            private_write(d/'policy-applied','true\n')
        run(self.command(t['name'],'up','-d'),timeout=600)
        return t['name']
    def snapshot(self,name,snapshot):
        identifier(snapshot); d=self.directory(name)
        target=d/'snapshots'/snapshot
        if target.exists():
            raise ValueError('Snapshot already exists')
        t=load(d/'topology.yaml'); saved=copy.deepcopy(compose(t)); completed=[]
        # Refuse volume-backed containers: docker commit excludes their contents.
        containers={}
        for s in saved['services']:
            ids=run(self.command(name,'ps','-q',s)).splitlines()
            if len(ids)!=1:
                raise ValueError(f'{s} must have exactly one running container')
            info=json.loads(run(['docker','inspect',ids[0]]))[0]
            if info.get('Mounts'):
                raise ValueError(f'{s} has mounts; filesystem-only snapshot refused')
            containers[s]=ids[0]
        try:
            for s,cid in containers.items():
                tag=f'lablink-snapshot/{name}-{s}:{snapshot}'
                run(['docker','commit','--pause=true',cid,tag],timeout=600)
                completed.append(tag); saved['services'][s]['image']=tag
            private_write(target/'compose.yaml',yaml.safe_dump(saved))
        except Exception:
            for tag in completed:
                run(['docker','image','rm',tag])
            raise
        return str(target)
    def reset(self,name,snapshot):
        identifier(snapshot); d=self.directory(name)
        src=d/'snapshots'/snapshot/'compose.yaml'
        if not src.exists():
            raise ValueError('Unknown snapshot')
        saved=yaml.safe_load(src.read_text())
        for s in saved['services'].values():
            run(['docker','image','inspect',s['image']])
        private_write(d/'compose.yaml',src.read_text())
        run(self.command(name,'up','-d','--force-recreate','--pull','never'),timeout=600)
    def capture(self,name,zone,output,interface=None,wireshark=False,zeek=False):
        d=self.directory(name); t=load(d/'topology.yaml')
        if zone not in t['zones']:
            raise ValueError('Unknown zone')
        if not interface:
            net=json.loads(run(['docker','network','inspect',f'lablink-{name}_{zone}']))[0]
            interface=net.get('Options',{}).get('com.docker.network.bridge.name') or 'br-'+net['Id'][:12]
        identifier(interface)
        output=Path(output).resolve(); output.parent.mkdir(parents=True,exist_ok=True)
        if output.exists():
            raise ValueError('Capture file already exists')
        private_write(output,'')
        proc=subprocess.Popen(['tcpdump','-i',interface,'-U','-w',str(output)])
        viewer=None
        try:
            if wireshark:
                viewer=subprocess.Popen(['wireshark','-r',str(output)])
            print('Capture running; Ctrl+C to stop')
            proc.wait()
        except KeyboardInterrupt:
            proc.send_signal(2); proc.wait(timeout=15)
        finally:
            if proc.poll() is None:
                proc.terminate(); proc.wait(timeout=15)
        if proc.returncode not in (0,-2):
            raise RuntimeError('tcpdump capture failed')
        if zeek:
            logdir=output.with_suffix('.zeek'); logdir.mkdir(exist_ok=True)
            subprocess.run(['zeek','-r',str(output)],cwd=logdir,check=True)
        return str(output)
