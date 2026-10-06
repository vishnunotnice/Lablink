import copy
from pathlib import Path
import pytest
import yaml
from lablink.labs import load,compose,policy,Labs
from lablink.system import identifier,private_write
from lablink.protect import quote
from lablink.cli import parser,lifetime

TEMPLATE=Path(__file__).parents[1]/'lablink/templates/ad-pentest.yaml'


def test_internal_networks():
    t=load(TEMPLATE); c=compose(t)
    assert all(n['internal'] for n in c['networks'].values())
    assert all('ports' not in s and 'privileged' not in s for s in c['services'].values())


def test_policy_scoped():
    text=policy(load(TEMPLATE))
    assert 'flush ruleset' not in text
    assert 'ip saddr 172.28.0.0/16 drop' in text
    assert 'tcp dport { 80, 389, 636 } accept' in text
    assert 'policy accept' in text

@pytest.mark.parametrize('mutation',[
    lambda t:t['zones']['targets'].update(cidr='172.28.10.0/24'),
    lambda t:t['services']['kali'].update(privileged=True),
    lambda t:t['allowed_flows'][0].update(ports=['80;drop']),
    lambda t:t.update(name='../oops')])
def test_bad_topology(tmp_path,mutation):
    t=load(TEMPLATE); mutation(t); f=tmp_path/'bad.yaml'; f.write_text(yaml.safe_dump(t))
    with pytest.raises(ValueError): load(f)


def test_private_write(tmp_path):
    p=tmp_path/'secret'; private_write(p,'value'); assert p.stat().st_mode & 0o777 == 0o600
    private_write(p,'new'); assert p.read_text()=='new'


def test_cli():
    assert parser().parse_args(['up','--template','ad-pentest']).template=='ad-pentest'
    assert lifetime('2h')==7200
    with pytest.raises(ValueError): lifetime('-1h')


def test_systemd_escaping():
    assert '%%' in quote('/tmp/100%')
    with pytest.raises(ValueError): quote('x\nExecStart=evil')


def test_snapshot_refuses_mounts(tmp_path,monkeypatch):
    labs=Labs(tmp_path); d=labs.directory('ad-pentest'); d.mkdir(parents=True)
    (d/'topology.yaml').write_text(TEMPLATE.read_text())
    calls=[]
    def fake(argv,**kwargs):
        calls.append(argv)
        if argv[0]=='docker' and argv[1]=='inspect': return '[{"Mounts":[{"Type":"volume"}]}]'
        return 'containerid'
    monkeypatch.setattr('lablink.labs.run',fake)
    with pytest.raises(ValueError,match='mounts'): labs.snapshot('ad-pentest','baseline')
    assert not any('commit' in call for call in calls)
