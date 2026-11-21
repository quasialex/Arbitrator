"""v0.14 integration validation: real export semantics, mocked provider responses."""
from __future__ import annotations

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.connectors import (
    ConnectorError, build_tenable_filters, check_tenable_connection,
    check_servicenow_connection, save_tenable_credentials, save_servicenow_credentials,
)
from app.servicenow import search_groups, select_group
from app.models import UserAccount, Owner, ServiceNowGroupMapping

@pytest.fixture
def account(db_session, monkeypatch):
    monkeypatch.setenv('ARBITRATOR_CREDENTIAL_KEY',Fernet.generate_key().decode())
    user=UserAccount(username='integration',name='Integration Analyst',email='user@example.test',password_hash='x')
    db_session.add(user);db_session.commit()
    return user


def test_filtered_tenable_export_cidr_family_state():
    filters,_=build_tenable_filters(cidr_range='10.20.3.14/24',
                                   plugin_family='Web Servers, General',
                                   severity_modification_type=['NONE','RECASTED'],
                                   days=14,severities=['low','info'])
    assert filters['cidr_range']=='10.20.3.0/24'
    assert filters['plugin_family']==['Web Servers','General']
    assert filters['severity_modification_type']==['NONE','RECASTED']
    assert set(filters['severity'])=={'low','info'}
    for value in ('10.20.500.0/24','not-an-ip'):
        with pytest.raises(ConnectorError):build_tenable_filters(cidr_range=value)
    with pytest.raises(ConnectorError):build_tenable_filters(severity_modification_type=['UNTRUSTED'])


def test_tenable_connection_distinguishes_saved_from_verified(db_session,account):
    save_tenable_credentials(db_session,account.id,'saved_access_123','saved_secret_456')
    def ok(request):
        assert request.url.path=='/users'
        assert 'saved_access_123' in request.headers['X-ApiKeys']
        return httpx.Response(200,json={'users':[{'id':1}]})
    with httpx.Client(base_url='https://cloud.tenable.com',transport=httpx.MockTransport(ok)) as client:
        assert 'accepted' in check_tenable_connection(db_session,account.id,client=client)
    with httpx.Client(base_url='https://cloud.tenable.com',transport=httpx.MockTransport(lambda req:httpx.Response(401))) as client:
        with pytest.raises(ConnectorError,match='401'):check_tenable_connection(db_session,account.id,client=client)


def test_servicenow_search_retains_group_metadata_and_verifies_selection(db_session,account):
    save_servicenow_credentials(db_session,account.id,'https://demo.service-now.com','robot','password123')
    team=Owner(name='API Team',email='team@example.test');db_session.add(team);db_session.commit()
    def handler(request):
        assert request.url.path.startswith('/api/now/table/sys_user_group')
        if request.url.path.endswith('/'+('a'*32)):
            return httpx.Response(200,json={'result':{'sys_id':'a'*32,'name':'API Platform Support','email':'api@example.test','active':'true'}})
        assert 'sysparm_query' in request.url.params
        assert 'nameLIKEAPI' in request.url.params['sysparm_query']
        return httpx.Response(200,json={'result':[
            {'sys_id':'a'*32,'name':'API Platform Support','email':'api@example.test'},
            {'sys_id':'b'*32,'name':'API Product Team','email':''}]})
    with httpx.Client(base_url='https://demo.service-now.com',transport=httpx.MockTransport(handler)) as client:
        groups=search_groups(db_session,account.id,'API',client=client)
        assert len(groups)==2
        select_group(db_session,account.id,team.id,'a'*32,client=client)
    mapped=db_session.get(ServiceNowGroupMapping,team.id)
    assert mapped.group_name=='API Platform Support'
    assert mapped.group_email=='api@example.test'
    with pytest.raises(ConnectorError,match='Invalid group'):
        search_groups(db_session,account.id,'^active=false',client=None)


def test_servicenow_connectivity_is_group_directory_access(db_session,account):
    save_servicenow_credentials(db_session,account.id,'https://demo.service-now.com','robot','password123')
    def handler(request):
        return httpx.Response(200,json={'result':[]})
    with httpx.Client(base_url='https://demo.service-now.com',transport=httpx.MockTransport(handler)) as client:
        assert 'accessible' in check_servicenow_connection(db_session,account.id,client=client)


def test_forbid_unverified_service_now_selection(db_session,account):
    save_servicenow_credentials(db_session,account.id,'https://demo.service-now.com','robot','password123')
    team=Owner(name='Unverified Team');db_session.add(team);db_session.commit()
    with httpx.Client(base_url='https://demo.service-now.com',transport=httpx.MockTransport(
        lambda req: httpx.Response(404,json={'result':{}}))) as client:
        with pytest.raises(ConnectorError,match='404'):
            select_group(db_session,account.id,team.id,'a'*32,client=client)
    assert db_session.get(ServiceNowGroupMapping,team.id) is None


def test_connection_health_is_not_confused_with_saved_keys(db_session,account):
    from app.connectors import connection_check,record_connection_check
    save_tenable_credentials(db_session,account.id,'valid_access_123','valid_secret_456')
    assert connection_check(db_session,account.id,'tenable') is None
    record_connection_check(db_session,account.id,'tenable',True)
    assert connection_check(db_session,account.id,'tenable').success
    record_connection_check(db_session,account.id,'tenable',False)
    assert not connection_check(db_session,account.id,'tenable').success
    # Changing API keys invalidates the previously tested state.
    save_tenable_credentials(db_session,account.id,'different_access','different_secret')
    assert connection_check(db_session,account.id,'tenable') is None
