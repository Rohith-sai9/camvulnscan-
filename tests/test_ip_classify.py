from netsec_audit.scanner import classify_ip

def test_classify_ip():
    assert classify_ip("10.0.0.1") == "Class A"
    assert classify_ip("172.16.0.1") == "Class B"
    assert classify_ip("192.168.1.1") == "Class C"
    assert classify_ip("230.0.0.1") == "Reserved or Multicast (Class D/E)"
    assert classify_ip("999.0.0.1") == "Invalid IP"
    assert classify_ip("abc.def") == "Invalid IP"
