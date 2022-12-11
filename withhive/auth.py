from .utils import hive_signed_request, hive_auth_crypto
from .constants import HIVE_API_GUEST_GENERATE, HIVE_API_GUEST_LOGIN, HIVE_API_AUTH, HIVE_AUTH_PAGE, HIVE_API_LOGIN, HIVE_API_OTP, HIVE_API_OTP_COMPLETE, HIVE_API_AUTH_BODY

import hashlib
import requests
import json
from urllib.parse import urlparse, parse_qs

class HiveUser:
    """Superclass for Hive authentication which should not be used directly."""
    HIVE_UID = None
    PEPPERMINT_TOKEN = None

    def __init__(self, uid = None):
        """
        Initialize a Hive user without authentication information.
        Parameters
        ----------
        uid : int or string
            If provided, Hive will attempt to use the provided UID for authentication.
        """
        self.HIVE_UID = uid
        self.PEPPERMINT_TOKEN = None

    def authenticate(self):
        """Authenticate a Hive user using information provided. This should be implemented by concrete Hive authentication types."""
        raise NotImplementedError

# Full Hive user - currently unsupported. Intended for use with login credentials.
class HiveFullUser(HiveUser):
    SESSION_KEY = None

    def parse_login(self, scheme):
        parsed = urlparse(scheme)
        params = parse_qs(parsed.query)
        if int(params['error_code'][0]) != 0: raise HiveAuthException(f"Failed to login to Hive with authenticated user - login completed but error code is {params['error_code'][0]}")
        self.HIVE_UID = params['uid'][0]
        self.PEPPERMINT_TOKEN = params['peppermint'][0].replace(" ", "+")
        self.SESSION_KEY = params['sessionkey'][0]

    """Represents a full Hive user with a verified account."""
    def authenticate(self, username = None, password = None):
        s = requests.Session()
        s.post(HIVE_API_AUTH, json=HIVE_API_AUTH_BODY)

        lk_text = s.get(HIVE_AUTH_PAGE)
        lk = lk_text.text.split('id="lk" value="')[1].split('"')[0]
        dkagh = hashlib.md5(password.encode('utf-8')).hexdigest()

        login_response = s.post(HIVE_API_LOGIN, data={"id": username, "lk": lk, "dkagh": dkagh})
        
        if login_response.json()['res_data']['scheme'] == "../acv_otp_main":
            hive_otp = input(f"Hive auth for this user requires MFA. Please enter MFA code: ")
            hive_otp = int(hive_otp)

            body = hive_auth_crypto(json.dumps({"code": f"{hive_otp}"}))
            print(body)

            otp_response = s.post(HIVE_API_OTP, json=body)
            print(otp_response)
            print(otp_response.text)

            otp_complete = s.get(HIVE_API_OTP_COMPLETE)
            print(otp_complete)
            print(otp_complete.headers)
            print(otp_complete.text)

        elif "c2shub://login" in login_response.json()['res_data']['scheme']:
            self.parse_login(login_response.json()['res_data']['scheme'])
        else:
            raise HiveAuthException(f"Failed to login to Hive with authenticated user - incorrect post-login scheme: {login_response.json()['res_data']['scheme']}")

# Represents a Guest user to the Hive authentication system. Guest users are nice and simple to use.
# The HiveGuestUser class will handle authentication steps, and can optionally use a pre-existing guest UID to avoid the overhead of setting up a new Guest every time the system is restarted.
class HiveGuestUser(HiveUser):
    """Represents a Hive guest user without concrete authentication details."""

    def __init__(self, uid = None):
        super().__init__(uid)

    def authenticate(self):
        """
        Authenticates a Hive guest user using the UID provided. If no UID was provided, a new UID will be automatically generated for the user.
        It's recommended to generate a UID once, then provide the same UID for authentication as a guest in the future.
        """
        # no need to re-auth if peppermint token already filled
        if self.PEPPERMINT_TOKEN != None: return

        # run through generation steps if the UID was not provided
        if self.HIVE_UID == None:
            generated = hive_signed_request(HIVE_API_GUEST_GENERATE)
            if 'guest_uid' not in generated: raise HiveAuthException("Failed to generate new guest UID in Hive")
            self.HIVE_UID = generated['guest_uid']

        # authenticate with the guest UID
        login = hive_signed_request(HIVE_API_GUEST_LOGIN, {'guest_uid': self.HIVE_UID})
        if 'peppermint_guest' not in login: raise HiveAuthException("Failed to authenticate with guest UID in Hive")
        self.PEPPERMINT_TOKEN = login['peppermint_guest']

# exception thrown while authenticating to the Hive API
class HiveAuthException(Exception):
    pass
