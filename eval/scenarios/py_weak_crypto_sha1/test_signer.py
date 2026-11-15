from service import sign_api_token

def test_signature_length():
    sig = sign_api_token("test_payload")
    assert isinstance(sig, str)
    assert len(sig) >= 32

