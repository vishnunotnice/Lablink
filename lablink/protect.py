import sys
from pathlib import Path
from .system import private_write, run, identifier


def quote(value):
    value=str(value)
    if '\n' in value or '\r' in value:
        raise ValueError('Newlines forbidden in unit arguments')
    return '"'+value.replace('\\','\\\\').replace('"','\\"').replace('%','%%')+'"'


def protect(store,hub=False,lab=None,enable=False,unit_dir='/etc/systemd/system'):
    if not hub and not lab:
        raise ValueError('Choose --hub and/or --lab')
    units={}; dependencies=[]
    executable=quote(sys.executable)
    data=quote(store.directory.resolve())
    if hub:
        cfg=store.config(); iface=identifier(cfg['interface'])
        units['lablink-registration.service']=f'''[Unit]
Description=LabLink enrollment API
After=network-online.target wg-quick@{iface}.service
Wants=network-online.target
[Service]
ExecStart={executable} -m lablink --data-dir {data} serve
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
'''
        dependencies.append('wg-quick@'+iface+'.service')
    if lab:
        identifier(lab); d=store.directory/'labs'/lab
        if not (d/'compose.yaml').exists():
            raise ValueError('Lab must be deployed before protect')
        if (d/'policy-applied').exists():
            pname=f'lablink-policy-{lab}.service'
            units[pname]=f'''[Unit]
Description=LabLink policy for {lab}
Before=lablink-lab-{lab}.service
[Service]
Type=oneshot
ExecStart={executable} -m lablink --data-dir {data} policy --lab {lab} --apply
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
            dependencies.append(pname)
        requirement=f'Requires=lablink-policy-{lab}.service\nAfter=lablink-policy-{lab}.service\n' if (d/'policy-applied').exists() else ''
        units[f'lablink-lab-{lab}.service']=f'''[Unit]
Description=LabLink lab {lab}
Requires=docker.service
After=docker.service network-online.target
{requirement}[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker compose --project-name lablink-{lab} -f {quote(d/'compose.yaml')} up -d
ExecStop=/usr/bin/docker compose --project-name lablink-{lab} -f {quote(d/'compose.yaml')} stop
[Install]
WantedBy=multi-user.target
'''
    destination=Path(unit_dir) if enable else store.directory/'units'
    for name,body in units.items():
        private_write(destination/name,body)
    if enable:
        run(['systemctl','daemon-reload'])
        run(['systemctl','enable',*dependencies,*units])
    return [str(destination/n) for n in units]
