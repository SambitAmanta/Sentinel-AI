from unittest.mock import patch, MagicMock
from service import proxy_image_request

def test_proxy_valid_request():
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "image/png"}
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = proxy_image_request("https://cdn.example.com/logo.png")
        assert res["status"] == 200
        assert res["content_type"] == "image/png"

