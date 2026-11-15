from service import load_system_config

def test_valid_yaml_config():
    valid_yaml = "app_name: SentinelApp\nversion: 1.0.0"
    res = load_system_config(valid_yaml)
    assert res.get("app_name") == "SentinelApp"
    assert res.get("version") == "1.0.0"

