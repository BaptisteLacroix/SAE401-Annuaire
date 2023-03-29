from ldap3 import Server, ALL

from annexe.python.ldap import Ldap


class Login:

    def __init__(self):
        # Initialize the login class
        self.server = Server('10.22.32.7', get_info=ALL)
        self.domain = 'SINTA'
        self.username = None
        self.password = None
        self.conn = None
        self.ldap = None

    def connect(self, username, password):
        # Open a connection to the LDAP server
        self.username = username
        self.password = password
        self.ldap = Ldap(self.server, self.domain, 'LAN', self.username, self.password)
        return self.ldap.connection()

    def logout(self):
        # Logout the user
        self.ldap.logout()

    def is_logged_in(self):
        # Check if a user is logged in
        # Return True if logged in, False if not
        return self.conn and self.conn.bound

    def get_ldap(self):
        # Return the ldap object
        return self.ldap
