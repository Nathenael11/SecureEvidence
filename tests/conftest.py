# -*- coding: utf-8 -*-
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.user_store import init_user_db, create_user, get_user_by_username
from backend.security import create_jwt_token, login_limiter, public_verifier_limiter

@pytest.fixture(autouse=True)
def auto_auth_headers(monkeypatch, request):
    login_limiter.reset()
    public_verifier_limiter.reset()
    init_user_db()
    
    # In test_auth.py, do not inject auto auth headers so auth tests can test unauthenticated / specific logins
    if 'test_auth' in request.node.fspath.basename:
        return

    if not get_user_by_username('test_investigator'):
        create_user('test_investigator', 'Test Senior Investigator', 'investigator', 'SecretPassword123!')
    
    token, _ = create_jwt_token(
        subject='test_investigator',
        role='investigator',
        full_name='Test Senior Investigator',
        officer_id='INSA-INV-0001'
    )
    
    orig_request = TestClient.request

    def request_with_auth(self, method, url, *args, **kwargs):
        headers = kwargs.get('headers')
        if headers is None:
            kwargs['headers'] = {'Authorization': f'Bearer {token}'}
        elif isinstance(headers, dict) and 'Authorization' not in headers:
            headers['Authorization'] = f'Bearer {token}'
            kwargs['headers'] = headers
        return orig_request(self, method, url, *args, **kwargs)

    monkeypatch.setattr(TestClient, 'request', request_with_auth)

@pytest.fixture(autouse=True)
def setup_test_ledger(tmp_path, request):
    if 'test_ledger_sqlite' in request.node.fspath.basename or 'test_e2e_playwright' in request.node.fspath.basename or 'test_blockchain_real' in request.node.fspath.basename:
        yield
        return

    test_db = str(tmp_path / "test_ledger_fixture.db")
    from blockchain.ledger_store import SqliteLedgerStore, set_ledger_store
    from blockchain.web3_client import Web3EvidenceClient
    from backend.services.evidence_service import EvidenceService
    from backend.config import settings

    temp_store = SqliteLedgerStore(test_db)
    set_ledger_store(temp_store)
    EvidenceService._instance = Web3EvidenceClient(
        rpc_url=settings.RPC_URL,
        contract_address=settings.CONTRACT_ADDRESS,
        store=temp_store
    )

    yield

    temp_store.close()
    set_ledger_store(None)
    EvidenceService._instance = None
