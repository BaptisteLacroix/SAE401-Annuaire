from ldap3 import Connection, SIMPLE, SYNC, Server, ALL


class Login:

    def __init__(self, username, password):
        # Initialize the login class
        self.server = Server('10.22.32.3', get_info=ALL)
        self.domain = 'SINTA'
        self.username = username
        self.password = password
        self.conn = None

    def connect(self):
        # Open a connection to the LDAP server
        self.conn = Connection(self.server,
                               user=f'{self.username}@{self.domain}.LAN',
                               password=self.password,
                               authentication=SIMPLE,
                               client_strategy=SYNC,
                               raise_exceptions=True)
        self.conn.bind()
        return self.conn.bound

    def login(self, username, password):
        # Check if the user exists in the active directory
        """
        self.connect()
        self.conn.search(search_base='DC={},DC=LAN'.format(self.domain),
                         search_filter='(sAMAccountName={})'.format(username),
                         search_scope='SUBTREE',
                         attributes=['dn'])
        if len(self.conn.entries) == 0:
            return False
        user_dn = self.conn.entries[0].dn
        try:
            user_conn = Connection(self.server, user=user_dn, password=password, authentication=SIMPLE,
                                   client_strategy=SYNC, raise_exceptions=True)
            user_conn.bind()
            return True
        except Exception:
            return False
            """

    def logout(self):
        # Logout the user
        self.conn.unbind()

    def is_logged_in(self):
        # Check if a user is logged in
        # Return True if logged in, False if not
        return self.conn and self.conn.bound
