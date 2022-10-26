from .utils import hive_signed_request
from .constants import HIVE_API_GUEST_GENERATE, HIVE_API_GUEST_LOGIN

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
    """Represents a full Hive user with a verified account. Currently support for full Hive users is limited."""
    def authenticate(self, uid = None):
        raise HiveAuthException("Full Hive users are not yet supported. Use HiveGuestUser instead.")

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
