#!/usr/bin/env python3
"""
Regression tests for scripts/ldap_hunt.py — synthetic EVE records, no real data.

    python3 -I tests/test_ldap_hunt.py        (from the hunt-ldap skill folder)

Each test builds a tiny eve.json for one attack (or one benign look-alike), runs the
script and checks the section output. Secret values planted in the fixtures must
never appear in stdout or in any artifact.
"""
import json, os, struct, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, '..', 'scripts', 'ldap_hunt.py')
SECRETS = ('SuperSecret1!', 'NewPassw0rd!', 'GuessPass9')

DC, DC_NAME, DOM = '10.0.0.1', 'dc01.corp.local', 'corp.local'


# ----------------------------------------------------------------------------- builders
def ntlm3(dom, user, ws, flags=0x00088215 | 0x10):
    d, u, w = (x.encode('utf-16le') for x in (dom, user, ws))
    nt = b'\x11' * 48
    fields, payload, off = [], b'', 64
    for blob in (b'', nt, d, u, w, b''):
        fields.append(struct.pack('<HHI', len(blob), len(blob), off + len(payload)))
        payload += blob
    return (b'NTLMSSP\x00' + struct.pack('<I', 3) + b''.join(fields)
            + struct.pack('<I', flags) + payload).hex()

def krb_ms_oid():
    # SPNEGO NegTokenInit listing only the MS krb5 OID
    return ('6082000506062b0601050502a0' + '30' + '06092a864882f712010202' + '00' * 20)

def _labels(name):
    out = b''
    for part in name.split('.') if name else []:
        out += bytes([len(part)]) + part.encode()
    return out + b'\x00'

def netlogon(opcode, user=''):
    b = struct.pack('<HHI', opcode, 0, 0x3f3fd) + b'\x00' * 16
    for nm in (DOM, DOM, DC_NAME, 'CORP', 'DC01', user, 'Default-First-Site', 'Default-First-Site'):
        b += _labels(nm)
    # Suricata escapes non-UTF-8 bytes as literal \xNN text
    return ''.join(chr(c) if 0x20 <= c < 0x7f and c != 0x5c else '\\x%02x' % c for c in b)

def ldap(ts, src, dst, request=None, responses=None, fid=1, proto='TCP', dport=389):
    l = {}
    if request is not None: l['request'] = request
    if responses is not None: l['responses'] = responses
    return {'timestamp': ts, 'flow_id': fid, 'event_type': 'ldap', 'src_ip': src, 'dest_ip': dst,
            'src_port': 50000, 'dest_port': dport, 'proto': proto, 'ldap': l}

def bind_ntlm(ts, src, user, rc, ws='WS1', msg='', flags=0x00088215 | 0x10, fid=1, dst=DC):
    return ldap(ts, src, dst, {'operation': 'bind_request', 'bind_request': {
        'version': 3, 'name': '', 'sasl': {'mechanism': 'GSS-SPNEGO', 'credentials': ntlm3('CORP', user, ws, flags)}}},
        [{'operation': 'bind_response', 'bind_response': {'result_code': rc, 'message': msg}}], fid)

def bind_simple(ts, src, name, rc, fid=1, dst=DC):
    return ldap(ts, src, dst, {'operation': 'bind_request', 'bind_request': {'version': 3, 'name': name}},
                [{'operation': 'bind_response', 'bind_response': {'result_code': rc, 'message': ''}}], fid)

def search(ts, src, base, attrs, entries=0, controls=None, fid=1, scope='wholeSubtree', dst=DC):
    req = {'operation': 'search_request', 'search_request': {'base_object': base, 'scope': scope,
           'attributes': attrs}}
    if controls: req['controls'] = [{'control_type': c, 'criticality': True} for c in controls]
    resp = [{'operation': 'search_result_entry', 'search_result_entry': {
        'base_object': 'CN=u%d,%s' % (i, base), 'attributes': [{'type': 'sAMAccountName', 'values': ['u%d' % i]}]}}
        for i in range(entries)]
    resp.append({'operation': 'search_result_done', 'search_result_done': {'result_code': 'success', 'message': ''}})
    return ldap(ts, src, dst, req, resp, fid)

def cldap_ping(ts, src, opcode, user):
    return ldap(ts, src, DC, {'operation': 'search_request', 'search_request': {
        'base_object': '', 'scope': 'baseObject', 'attributes': ['Netlogon']}},
        [{'operation': 'search_result_entry', 'search_result_entry': {'base_object': '',
          'attributes': [{'type': 'Netlogon', 'values': [netlogon(opcode, user)]}]}}], proto='UDP', fid=9)

def modify(ts, src, obj, attr, values, rc='success', op='replace', fid=1):
    return ldap(ts, src, DC, {'operation': 'modify_request', 'modify_request': {'object': obj, 'changes': [
        {'operation': op, 'modification': {'attribute_type': attr, 'attribute_values': values}}]}},
        [{'operation': 'modify_response', 'modify_response': {'result_code': rc, 'message': ''}}], fid)

def flow(src, dst, proto, dport, pts, bts, ptc, btc, app='ldap'):
    e = {'timestamp': '2026-01-01T09:00:00', 'flow_id': 77, 'event_type': 'flow', 'src_ip': src,
         'dest_ip': dst, 'dest_port': dport, 'proto': proto,
         'flow': {'pkts_toserver': pts, 'bytes_toserver': bts, 'pkts_toclient': ptc,
                  'bytes_toclient': btc, 'tx_cnt': 1, 'age': 1, 'start': '2026-01-01T09:00:00'}}
    if app: e['app_proto'] = app
    return e

BASE_DC = [  # every scenario gets a DC inventory: WS1 (10.0.0.20) locates the DC as WS1$
    cldap_ping('2026-01-01T08:00:00', '10.0.0.20', 23, 'WS1$'),
]


class HuntTest(unittest.TestCase):
    def run_hunt(self, events, *args):
        self.tmp = tempfile.mkdtemp()
        p = os.path.join(self.tmp, 'eve.json')
        with open(p, 'w') as fh:
            for e in BASE_DC + events:
                fh.write(json.dumps(e) + '\n')
        self.art = os.path.join(self.tmp, 'art')
        out = subprocess.run([sys.executable, '-I', SCRIPT, p, '--artifacts', self.art] + list(args),
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.out = out.stdout
        return out.stdout

    def section(self, name):
        s = self.out.split('=== %s' % name, 1)[1]
        return s.split('\n=== ', 1)[0]

    # ------------------------------------------------------------------ H4 relay
    def test_relay_dc_account_same_workstation_name(self):
        self.run_hunt([bind_ntlm('2026-01-01T10:00:00', '10.0.0.66', 'DC01$', 'success', ws='DC01')])
        h4 = self.section('H4')
        self.assertIn('RELAY: machine acct DC01$ bound from 10.0.0.66', h4)
        self.assertIn('DC ACCOUNT — coerced DC auth relayed', h4)

    def test_relay_machine_account_from_foreign_ip(self):
        self.run_hunt([bind_ntlm('2026-01-01T10:00:00', '10.0.0.66', 'WS1$', 'success', ws='WS1')])
        self.assertIn('RELAY: machine acct WS1$ bound from 10.0.0.66 but ws1 is seen at 10.0.0.20', self.section('H4'))

    def test_machine_account_from_own_ip_is_quiet(self):
        self.run_hunt([bind_ntlm('2026-01-01T10:00:00', '10.0.0.20', 'WS1$', 'success', ws='WS1')])
        self.assertIn('none', self.section('H4').split('relay / misuse indicators')[1])

    def test_machine_account_nosign(self):
        self.run_hunt([bind_ntlm('2026-01-01T10:00:00', '10.0.0.20', 'WS1$', 'success', ws='WS1',
                                 flags=0x00088215 & ~0x10)])
        h4 = self.section('H4')
        self.assertIn('without SIGN', h4)
        self.assertIn('unsigned successful bind', h4)

    # ------------------------------------------------------------------ H5
    def test_spray_then_success(self):
        ev = [bind_ntlm('2026-01-01T10:00:0%d' % i, '10.0.0.50', u, 'invalid_credentials',
                        msg='AcceptSecurityContext error, data 52e, v4563') for i, u in enumerate('abcde')]
        ev.append(bind_ntlm('2026-01-01T10:00:09', '10.0.0.50', 'f', 'success'))
        self.run_hunt(ev)
        h5 = self.section('H5')
        self.assertIn('SPRAY\n', h5)
        self.assertIn('SPRAY->SUCCESS', h5)
        self.assertIn('CORP\\f@WS1', h5)

    def test_brute_then_success_simple_bind(self):
        ev = [bind_simple('2026-01-01T10:00:0%d' % i, '10.0.0.51', 'CN=svc,DC=corp,DC=local',
                          'invalid_credentials') for i in range(3)]
        ev.append(bind_simple('2026-01-01T10:00:08', '10.0.0.51', 'CN=svc,DC=corp,DC=local', 'success'))
        self.run_hunt(ev)
        self.assertIn('BRUTE->SUCCESS', self.section('H5'))

    def test_distributed_failures_one_identity(self):
        ev = [bind_ntlm('2026-01-01T10:00:0%d' % i, '10.0.1.%d' % i, 'admin', 'invalid_credentials',
                        msg='data 52e') for i in range(5)]
        self.run_hunt(ev)
        self.assertIn('corp\\admin', self.section('H5').split('many sources')[1])

    # ------------------------------------------------------------------ H6b
    def test_anonymous_bind_then_search(self):
        self.run_hunt([bind_simple('2026-01-01T10:00:00', '10.0.0.70', '', 'success', fid=5),
                       search('2026-01-01T10:00:01', '10.0.0.70', 'DC=corp,DC=local', ['sAMAccountName'],
                              entries=3, fid=5)])
        h = self.section('H6b')
        self.assertIn('ENTRIES RETURNED ANONYMOUSLY', h)
        self.assertIn('entries=3', h)

    # ------------------------------------------------------------------ H8 writes
    def test_nopac_rename(self):
        self.run_hunt([modify('2026-01-01T10:00:00', '10.0.0.66', 'CN=WS9,OU=Servers,DC=corp,DC=local',
                              'sAMAccountName', ['DC01'])])
        self.assertIn('NOPAC: sAMAccountName set to a DC name without $', self.section('H8'))

    def test_dacl_on_domain_root(self):
        self.run_hunt([modify('2026-01-01T10:00:00', '10.0.0.66', 'DC=corp,DC=local',
                              'nTSecurityDescriptor', ['\\x01\\x00'])])
        self.assertIn('DACL WRITE ON DOMAIN ROOT', self.section('H8'))

    def test_machine_add_outside_computers_container(self):
        self.run_hunt([ldap('2026-01-01T10:00:00', '10.0.0.66', DC, {'operation': 'add_request', 'add_request': {
            'entry': 'CN=EVIL,OU=Servers,DC=corp,DC=local', 'attributes': [
                {'name': 'objectClass', 'values': ['top', 'person', 'user', 'computer']},
                {'name': 'sAMAccountName', 'values': ['EVIL$']},
                {'name': 'unicodePwd', 'values': ['"SuperSecret1!"']}]}})])
        h8 = self.section('H8')
        self.assertIn('machine-account-add', h8)
        self.assertIn('secret:password', h8)

    def test_privileged_group_and_no_ou_false_positive(self):
        self.run_hunt([modify('2026-01-01T10:00:00', '10.0.0.66', 'CN=Domain Admins,CN=Users,DC=corp,DC=local',
                              'member', ['CN=x,DC=corp,DC=local'], op='add'),
                       modify('2026-01-01T10:00:01', '10.0.0.66', 'CN=bob,OU=IT Administrators,DC=corp,DC=local',
                              'description', ['hi'])])
        lines = self.section('H8').splitlines()
        self.assertTrue(any('Domain Admins' in l and 'PRIVILEGED-GROUP' in l for l in lines))
        self.assertFalse(any('IT Administrators' in l and 'PRIVILEGED-GROUP' in l for l in lines))

    def test_upn_and_altsecid_writes(self):
        self.run_hunt([modify('2026-01-01T10:00:00', '10.0.0.66', 'CN=bob,DC=corp,DC=local',
                              'userPrincipalName', ['administrator']),
                       modify('2026-01-01T10:00:01', '10.0.0.66', 'CN=bob,DC=corp,DC=local',
                              'altSecurityIdentities', ['X509:<I>x<S>y'])])
        h8 = self.section('H8')
        self.assertIn('ESC9/ESC10', h8)
        self.assertIn('ESC14', h8)

    # ------------------------------------------------------------------ H9 controls
    def test_dirsync_ex_and_bloodhound_controls_with_source(self):
        self.run_hunt([search('2026-01-01T10:00:00', '10.0.0.66', 'DC=corp,DC=local', ['sAMAccountName'],
                              controls=['1.2.840.113556.1.4.2090']),
                       search('2026-01-01T10:00:01', '10.0.0.67', 'DC=corp,DC=local', ['nTSecurityDescriptor'],
                              controls=['1.2.840.113556.1.4.801', '1.2.840.113556.1.4.319'])])
        h9 = self.section('H9')
        self.assertIn('10.0.0.66 -> 10.0.0.1  1.2.840.113556.1.4.2090  DirSync_EX', h9)
        self.assertRegex(h9, r'10\.0\.0\.66\s+DIRSYNC from non-DC')
        self.assertRegex(h9, r'10\.0\.0\.67\s+SD_FLAGS \+ paged')

    # ------------------------------------------------------------------ H11
    def test_cldap_enumeration_reports_valid_users(self):
        ev = [cldap_ping('2026-01-01T10:00:0%d' % i, '10.0.0.88', 23, u) for i, u in enumerate(['alice', 'bob'])]
        ev += [cldap_ping('2026-01-01T10:01:0%d' % i, '10.0.0.88', 25, u) for i, u in enumerate(['x1', 'x2', 'x3', 'x4'])]
        self.run_hunt(ev)
        h11 = self.section('H11')
        self.assertIn("ENUMERATION: 10.0.0.88 probed 6 users — 2 VALID ['alice', 'bob'], 4 unknown", h11)
        self.assertNotIn('10.0.0.20 probed', h11)   # a host pinging as itself is not enumeration

    def test_rogue_ldap_server(self):
        self.run_hunt([bind_ntlm('2026-01-01T10:00:00', '10.0.0.20', 'alice', 'sasl_bind_in_progress', dst='10.0.0.99')])
        self.assertIn('10.0.0.99', self.section('H11').split('NOT known DCs')[1])

    # ------------------------------------------------------------------ H12
    def test_inbound_answered_and_cgnat_internal(self):
        self.run_hunt([flow('45.33.32.156', DC, 'UDP', 389, 1, 60, 1, 3000),
                       flow('100.64.1.1', DC, 'TCP', 389, 5, 500, 5, 900)])
        h12 = self.section('H12')
        self.assertIn('INBOUND ANSWERED', h12)
        self.assertIn('OPEN REFLECTOR', h12)
        self.assertNotIn('100.64.1.1', h12)

    # ------------------------------------------------------------------ H15 / H16 / H17
    def test_compare_password_oracle(self):
        ev = [ldap('2026-01-01T10:00:0%d' % i, '10.0.0.77', DC, {'operation': 'compare_request', 'compare_request': {
            'entry': 'uid=bob,dc=corp', 'attribute_value_assertion': {'description': 'userPassword', 'value': 'GuessPass9'}}},
            [{'operation': 'compare_response', 'compare_response': {'result_code': 'compare_false', 'message': ''}}])
            for i in range(5)]
        self.run_hunt(ev)
        self.assertIn('PASSWORD COMPARE: 10.0.0.77 sent 5 compare(s) against secret attributes — BRUTE FORCE',
                      self.section('H15'))

    def test_jndi_response_from_public_server(self):
        self.run_hunt([ldap('2026-01-01T10:00:00', '10.0.0.30', '93.184.216.34', {'operation': 'search_request',
            'search_request': {'base_object': 'a', 'scope': 'baseObject', 'attributes': []}},
            [{'operation': 'search_result_entry', 'search_result_entry': {'base_object': 'a', 'attributes': [
                {'type': 'javaClassName', 'values': ['foo']}, {'type': 'javaCodeBase', 'values': ['http://93.184.216.34/']},
                {'type': 'objectClass', 'values': ['javaNamingReference']}]}}], dport=1389)])
        h16 = self.section('H16')
        self.assertIn('javaCodeBase=http://93.184.216.34/', h16)
        self.assertIn('PUBLIC server', h16)

    def test_search_volume(self):
        self.run_hunt([search('2026-01-01T10:00:00', '10.0.0.66', 'DC=corp,DC=local', ['member'], entries=12)],
                      '--enum', '10')
        self.assertRegex(self.section('H17'), r'10\.0\.0\.66\s+searches=1 entries=12 root_subtree=1 .*ENUMERATION')

    # ------------------------------------------------------------------ misc
    def test_kerberos_ms_oid(self):
        self.run_hunt([ldap('2026-01-01T10:00:00', '10.0.0.20', DC, {'operation': 'bind_request', 'bind_request': {
            'version': 3, 'name': '', 'sasl': {'mechanism': 'GSS-SPNEGO', 'credentials': krb_ms_oid()}}})])
        self.assertIn('sasl:GSS-SPNEGO:kerberos', self.section('H1'))

    def test_extended_op_not_double_counted_and_value_hidden(self):
        self.run_hunt([ldap('2026-01-01T10:00:00', '10.0.0.66', DC, {'operation': 'extended_request',
            'extended_request': {'name': '1.3.6.1.4.1.4203.1.11.1', 'value': 'NewPassw0rd!'}},
            [{'operation': 'extended_response', 'extended_response': {'result_code': 'success', 'message': '',
              'name': '1.3.6.1.4.1.4203.1.11.1'}}])])
        self.assertRegex(self.section('H9'), r'\n\s+1  \(.*PasswordModify')

    def test_secrets_never_emitted(self):
        self.run_hunt([
            modify('2026-01-01T10:00:00', '10.0.0.66', 'CN=bob,DC=corp,DC=local', 'unicodePwd', ['"SuperSecret1!"']),
            ldap('2026-01-01T10:00:01', '10.0.0.66', DC, {'operation': 'extended_request',
                 'extended_request': {'name': '1.3.6.1.4.1.4203.1.11.1', 'value': 'NewPassw0rd!'}}),
            ldap('2026-01-01T10:00:02', '10.0.0.77', DC, {'operation': 'compare_request', 'compare_request': {
                 'entry': 'uid=bob', 'attribute_value_assertion': {'description': 'userPassword', 'value': 'GuessPass9'}}})])
        blobs = [self.out]
        for f in os.listdir(self.art):
            with open(os.path.join(self.art, f)) as fh:
                blobs.append(fh.read())
        for s in SECRETS:
            for b in blobs:
                self.assertNotIn(s, b)


REDACT = os.path.join(HERE, '..', 'scripts', 'redact.jq')

@unittest.skipUnless(subprocess.run(['sh', '-c', 'command -v jq'], capture_output=True).returncode == 0,
                     'jq not installed')
class RedactTest(unittest.TestCase):
    def jq(self, rec):
        out = subprocess.run(['jq', '-c', '-f', REDACT], input=json.dumps(rec), capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip()

    def test_secret_list_matches_script(self):
        sys.dont_write_bytecode = True        # keep the skill folder free of __pycache__
        sys.path.insert(0, os.path.join(HERE, '..', 'scripts'))
        import ldap_hunt
        with open(REDACT) as fh:
            src = fh.read()
        listed = set(__import__('re').findall(r'"([a-z0-9-]+)"', src.split('def SECRET:')[1].split('];')[0]))
        self.assertEqual(listed, ldap_hunt.SECRET_ATTRS)

    def test_secrets_redacted(self):
        recs = [
            bind_ntlm('2026-01-01T10:00:00', '10.0.0.66', 'bob', 'success'),
            modify('2026-01-01T10:00:00', '10.0.0.66', 'CN=bob,DC=corp', 'unicodePwd', ['"SuperSecret1!"']),
            ldap('2026-01-01T10:00:01', '10.0.0.66', DC, {'operation': 'extended_request',
                 'extended_request': {'name': '1.3.6.1.4.1.4203.1.11.1', 'value': 'NewPassw0rd!'}}),
            ldap('2026-01-01T10:00:02', '10.0.0.77', DC, {'operation': 'compare_request', 'compare_request': {
                 'entry': 'uid=bob', 'attribute_value_assertion': {'description': 'userPassword', 'value': 'GuessPass9'}}}),
            ldap('2026-01-01T10:00:03', '10.0.0.66', DC, {'operation': 'add_request', 'add_request': {
                 'entry': 'CN=EVIL,DC=corp', 'attributes': [{'name': 'unicodePwd', 'values': ['SuperSecret1!']}]}}),
            ldap('2026-01-01T10:00:04', '10.0.0.66', DC, None, [{'operation': 'search_result_entry',
                 'search_result_entry': {'base_object': 'CN=WS1', 'attributes': [
                     {'type': 'ms-Mcs-AdmPwd', 'values': ['SuperSecret1!']}]}}]),
        ]
        for rec in recs:
            out = self.jq(rec)
            for s in SECRETS:
                self.assertNotIn(s, out)
        self.assertNotIn('1111111111', self.jq(recs[0]))       # NT response bytes
        self.assertIn('truncated — credential material', self.jq(recs[0]))

    def test_other_records_pass_through_unchanged(self):
        for rec in (flow('10.0.0.1', DC, 'TCP', 389, 1, 2, 3, 4),
                    search('2026-01-01T10:00:00', '10.0.0.66', 'DC=corp', ['cn'], entries=1),
                    modify('2026-01-01T10:00:00', '10.0.0.66', 'CN=bob', 'description', ['hello'])):
            self.assertEqual(json.loads(self.jq(rec)), rec)


if __name__ == '__main__':
    unittest.main(verbosity=1)
