import ipaddress
from pathlib import Path
from .system import run, private_write, identifier


def render_hub(store):
    cfg=store.config()
    lines=["[Interface]",f"PrivateKey = {cfg['private_key']}",
           f"Address = {cfg['hub_ip']}/{ipaddress.ip_network(cfg['subnet']).prefixlen}",
           f"ListenPort = {cfg['port']}","MTU = 1420"]
    for n in store.nodes():
        if n['status']=='approved':
            lines += ["", "[Peer]", f"PublicKey = {n['pubkey']}", f"AllowedIPs = {n['ip']}/32"]
    return "\n".join(lines)+"\n"


def repair(store, apply=False, config_dir='/etc/wireguard'):
    cfg=store.config(); interface=identifier(cfg['interface'])
    text=render_hub(store)
    private_write(store.directory / (interface+'.conf'),text)
    if apply:
        private_write(Path(config_dir)/(interface+'.conf'),text)
        # wg syncconf requires wg-quick fields stripped and a real file.
        stripped=run(['wg-quick','strip',str(Path(config_dir)/(interface+'.conf'))])
        target=store.directory/'sync.conf'
        private_write(target,stripped+'\n')
        try:
            run(['wg','syncconf',interface,str(target)])
        finally:
            target.unlink(missing_ok=True)
    return text


def node_config(private, result):
    return f"""[Interface]
PrivateKey = {private}
Address = {result['ip']}/32
MTU = 1420

[Peer]
PublicKey = {result['hub_public_key']}
Endpoint = {result['endpoint']}
AllowedIPs = {result['subnet']}
PersistentKeepalive = 25
"""
