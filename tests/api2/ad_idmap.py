#!/usr/bin/env python3

# Author: Eric Turgeon
# License: BSD
# Location for tests into REST API of FreeNAS

import pytest
import sys
import os
import json
apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, POST, GET, DELETE, SSH_TEST, wait_on_job
from auto_config import ip, hostname, pool_name, password, user
from pytest_dependency import depends

AD_DOMAIN = "homedom.fun"
ADPASSWORD = "abcd1234$"
ADUSERNAME = "joiner"
ADNameServer = "192.168.1.125"
"""
try:
    from config import AD_DOMAIN, ADPASSWORD, ADUSERNAME, ADNameServer
except ImportError:
    Reason = 'ADNameServer AD_DOMAIN, ADPASSWORD, or/and ADUSERNAME are missing in conf
ig.py"'
    pytestmark = pytest.mark.skip(reason=Reason)
"""

BACKENDS = [
    "AD",
    "AUTORID",
    "LDAP",
    "NSS",
    "RFC2307",
    "TDB",
    "RID",
]

BACKEND_OPTIONS = None
WORKGROUP = None
job_id = None


@pytest.mark.dependency(name="SET_DNS")
def test_01_set_nameserver_for_ad(request):
    global payload
    payload = {
        "nameserver1": ADNameServer,
    }
    global results
    results = PUT("/network/configuration/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text


@pytest.mark.dependency(name="AD_ENABLED")
def test_02_enabling_activedirectory(request):
    depends(request, ["SET_DNS"])
    global payload, results, job_id
    payload = {
        "bindpw": ADPASSWORD,
        "bindname": ADUSERNAME,
        "domainname": AD_DOMAIN,
        "netbiosname": hostname,
        "dns_timeout": 15,
        "verbose_logging": True,
        "enable": True
    }
    results = PUT("/activedirectory/", payload)
    assert results.status_code == 200, results.text
    job_id = results.json()['job_id']


@pytest.mark.dependency(name="JOINED_AD")
def test_003_verify_the_job_id_is_successful(request):
    depends(request, ["AD_ENABLED"])
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])


@pytest.mark.dependency(name="AD_IS_HEALTHY")
def test_04_get_activedirectory_state(request):
    depends(request, ["JOINED_AD"])
    results = GET('/activedirectory/get_state/')
    assert results.status_code == 200, results.text
    assert results.json() == 'HEALTHY', results.text


@pytest.mark.dependency(name="GATHERED_BACKEND_OPTIONS")
def test_05_get_idmap_backend_options(request):
    """
    Create large set of SMB shares for testing registry.
    """
    depends(request, ["AD_IS_HEALTHY"])
    global BACKEND_OPTIONS
    global WORKGROUP 
    results = GET("/idmap/backend_options")
    assert results.status_code == 200, results.text
    BACKEND_OPTIONS = results.json()

    results = GET("/smb")
    assert results.status_code == 200, results.text
    WORKGROUP = results.json()['workgroup']


@pytest.mark.parametrize('backend', BACKENDS)
def test_06_test_backend_options(request, backend):
    """
    Tests for backend options are performend against
    the backend for the domain we're joined to
    (DS_TYPE_ACTIVEDIRECTORY) so that auto-detection
    works correctly. The three default idmap backends
    DS_TYPE_ACTIVEDIRECTORY, DS_TYPE_LDAP,
    DS_TYPE_DEFAULT_DOMAIN have hard-coded ids and
    so we don't need to look them up.
    """
    depends(request, ["GATHERED_BACKEND_OPTIONS"])
    opts = BACKEND_OPTIONS[backend]['parameters'].copy()

    payload = {
        "name": "DS_TYPE_ACTIVEDIRECTORY",
        "range_low": "1000000000",
        "range_high": "2000000000",
        "idmap_backend": backend,
        "options": {}
    }
    payload3 = {"options": {}}
    for k, v in opts.items():
        """
        Populate garbage data where an opt is required.
        This should get us past the first step of
        switching to the backend before doing more
        comprehensive tests.
        """
        if v['required']:
            payload["options"].update({k: "canary"})
        
    results = PUT("/idmap/id/1/", payload)
    assert results.status_code == 200, results.text
    idmap_id = results.json()['id']

    results = GET("/idmap/clear_idmap_cache")
    assert results.status_code == 200, results.text
    job_id = results.json()
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])

    if backend == "AUTORID":
        IDMAP_CFG = "idmap config * "
    else:
        IDMAP_CFG = f"idmap config {WORKGROUP} "

    """
    Validate that backend was correctly set in smb.conf.
    """
    cmd = f'midclt call smb.getparm "{IDMAP_CFG}: backend" GLOBAL'
    results = SSH_TEST(cmd, user, password, ip)
    assert results['result'] is True, results['output']
    running_backend = results['output'].strip()
    assert running_backend == backend.lower(), results['output'] 

    if backend == "RID":
        """
        sssd_compat generates a lower range based
        on murmur3 hash of domain SID. Since we're validating
        basic functionilty, checking that our range_low
        changed is sufficient for now.
        """
        payload2 = {"options": {"sssd_compat": True}}
        results = PUT("/idmap/id/1/", payload2)
        assert results.status_code == 200, results.text
        out = results.json()
        assert out['range_low'] != payload['range_low']

    elif backend == "AUTORID":
        """
        autorid is unique among the idmap backends because
        its configuration replaces the default idmap backend
        "idmap config *".
        """
        payload3["options"] = {
            "rangesize": 200000,
            "readonly": True,
            "ignore_builtin": True,
        }
        results = PUT("/idmap/id/1/", payload3)
        assert results.status_code == 200, results.text

    elif backend == "AD":
        payload3["options"] = {
            "schema_mode": "SFU",
            "unix_primary_group": True,
            "unix_nss_info": True,
        }
        results = PUT("/idmap/id/1/", payload3)
        assert results.status_code == 200, results.text

    elif backend == "LDAP":
        payload3["options"] = {
            "ldap_base_dn": "canary",
            "ldap_user_dn": "canary",
            "ldap_url": "canary",
            "readonly": True,
        }
        results = PUT("/idmap/id/1/", payload3)
        assert results.status_code == 200, results.text

    elif backend == "RFC2307":
        payload3["options"] = {
            "ldap_server": "stand-alone",
            "bind_path_user": "canary",
            "bind_path_group": "canary",
            "user_cn": True,
            "ldap_domain": "canary",
            "ldap_url": "canary",
            "ldap_user_dn": "canary",
            "ldap_user_dn_password": "canary",
            "ldap_realm": True,
        }
        results = PUT("/idmap/id/1/", payload3)
        assert results.status_code == 200, results.text
        r = payload3["options"].pop("ldap_realm")
        payload3["options"]["realm"] = r
        payload3["options"].pop("ldap_user_dn_password")
 
    results = GET("/idmap/clear_idmap_cache")
    assert results.status_code == 200, results.text
    job_id = results.json()
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])

    for k, v in payload3['options'].items():
        cmd = f'midclt call smb.getparm "{IDMAP_CFG} : {k}" GLOBAL'
        results = SSH_TEST(cmd, user, password, ip)
        assert results['result'] is True, results['output']
        try:
            res = json.loads(results['output'].strip())
            assert res == v, f"[{k}]: {res}" 
        except json.decoder.JSONDecodeError:
            res = results['output'].strip()
            if v is True:
                v = "Yes"
            elif v is False:
                v = "No"
            assert v.casefold() == res.casefold(), f"[{k}]: {res}"


def test_64_leave_activedirectory(request):
    depends(request, ["JOINED_AD"])
    global payload, results
    payload = {
        "username": ADUSERNAME,
        "password": ADPASSWORD
    }
    results = POST("/activedirectory/leave/", payload)
    assert results.status_code == 200, results.text


def test_65_remove_site(request):
    depends(request, ["JOINED_AD"])
    payload = {"site": None}
    results = PUT("/activedirectory/", payload)
    assert results.status_code == 200, results.text
