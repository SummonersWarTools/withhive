from hive.auth import HiveGuestUser

def test_hiveguestuser():
    guest = HiveGuestUser(uid = 90190698972)
    guest.authenticate()
    assert guest.HIVE_UID == 90190698972
    assert guest.PEPPERMINT_TOKEN is not None