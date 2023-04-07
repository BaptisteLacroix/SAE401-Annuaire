from typing import List

import ldap3


# It creates a connection to the LDAP server, and allows you to create
# organisations, groups and users, as well as search for them
class Ldap:

    def __init__(self, server, dc_name, dc_org, user, password):
        """
        *|MARCADOR_CURSOR|*

        :param dc_name: The name of the datacenter you want to connect to
        :param dc_org: The name of the organization that the datacenter is in
        :param user: The username to log in to the vCenter server
        :param password: The password for the user account you're using to connect to the vCenter server
        """
        self.user = user
        self.password = password
        self.conn = None
        self.server = server
        self.dc_name = dc_name
        self.dc_org = dc_org

    def __del__(self):
        """
        The __del__ method is called when the object is about to be destroyed
        """
        # Fermeture de la connexion à l'annuaire
        print("Fermeture de la connexion")
        self.conn.unbind()

    def connection(self):
        """
        The function takes the server IP address, the username, the password, the domain name and the organization name as
        parameters. It then creates a connection to the LDAP server and binds the connection to the user
        """
        # Connexion à l'annuaire Active Directory
        # Creating a connexion to the LDAP server.
        self.conn = ldap3.Connection(self.server, f'cn={self.user},cn=users,dc={self.dc_name},dc={self.dc_org}',
                                     self.password)

        print("Connexion à l'annuaire Active Directory")

        # Vérifier si la connexion a réussi
        if self.conn.bind():
            print("Connexion réussie")
            return True
        print("Echec de connexion")
        return False

    def create_organisation(self, organisation_name):
        """
        It creates an organizational unit (ou) in the LDAP directory

        :param organisation_name: The name of the organisation unit to be created
        """
        # Données de l'unité d'organisation
        ou_dn = f'ou={organisation_name},dc={self.dc_name},dc={self.dc_org}'
        ou_attributes = {
            'objectClass': ['top', 'organizationalUnit'],
            'ou': [organisation_name]
        }

        # Ajout de l'unité d'organisation
        self.conn.add(ou_dn, attributes=ou_attributes)

        # Vérification de la réussite de l'ajout
        if self.conn.result['result'] == 0:
            print("Unité d'organisation ajoutée avec succès")
            # show where the object was created
            print(f"Unité d'organisation créée à l'emplacement : {ou_dn}")
        else:
            print("Echec de l'ajout de l'unité d'organisation")

    def get_organiation_unit_by_name(self, organisation_name):
        """
        It searches for an organisation unit by its name in all the organisation units in the LDAP directory
        :param organisation_name: The name of the organisation unit to search for
        :return: The organisation unit if it exists, None otherwise
        """
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(ou={organisation_name})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['ou'])

        if self.conn.entries:
            return self.conn.entries[0].entry_dn
        return None

    def create_group(self, organisation_name, group_name):
        """
        It creates a group in the specified organisation

        :param organisation_name: The name of the organisation to which the group belongs
        :param group_name: The name of the group you want to create
        """
        # Données du groupe

        # Found the organisation_name and get the DN
        organisation_dn = self.get_organiation_unit_by_name(organisation_name)
        print(organisation_dn)
        if organisation_dn is None:
            print("L'unité d'organisation n'existe pas")
            return

        group_dn = f'cn={group_name},{organisation_dn}'
        group_attributes = {
            'objectClass': ['top', 'group'],
            'cn': [group_name]
        }

        # Ajout du groupe
        self.conn.add(group_dn, attributes=group_attributes)

        # Vérification de la réussite de l'ajout
        if self.conn.result['result'] == 0:
            print("Groupe ajouté avec succès")
        else:
            print("Echec de l'ajout du groupe")

    def found_group(self, group):
        """
        Found the group in the SINTA.LAN domain
        :param group: The name of the group to search for
        :return: the group if it exists, None otherwise
        """
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(cn={group})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['cn'])

        if self.conn.entries:
            return self.conn.entries[0].entry_dn
        return None

    def add_user_to_group(self, display_name, group_name):
        """
        It adds a user to a group

        :param display_name: The name of the user to add to the group
        :param group_name: The name of the group to add the user to
        """
        # Ajout de l'utilisateur au groupe
        group_cn = self.found_group(group_name)
        print(group_cn)
        if group_cn is None:
            print("Le groupe n'existe pas")
            return

        # for each user
        print(display_name)
        for user in display_name:
            user_cn = self.search_user(user)
            if user_cn is None:
                print("L'utilisateur n'existe pas")
                return
            print(user_cn[0].distinguishedName.value)
            self.conn.extend.microsoft.add_members_to_groups(
                f'{user_cn[0].distinguishedName.value}',
                [f'{group_cn}'])

            # Vérification de la réussite de l'ajout
            if self.conn.result['result'] == 0:
                print(f"Utilisateur {user} ajouté au groupe {group_name} avec succès")
            else:
                print("Echec de l'ajout de l'utilisateur au groupe")

    def search_all_object_class(self):
        """
        It searches the entire directory for all objects that have the objectClass attribute
        """
        # Recherche de toutes les entrées dans l'annuaire
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}', search_filter='(objectClass=*)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")

    def get_all_organisation_unit(self):
        """
        Get all the organisation unit from the SINTA.LAN ldap.
        :return: A list of all the organisation unit
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter='(objectClass=organizationalUnit)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['ou'])

        if not self.conn.entries:
            print("Aucune entrée trouvée")
            return []
        return [entry.ou.value for entry in self.conn.entries]

    def search_object_class(self, entrie_name):
        """
        It searches the LDAP server for entries with the objectClass attribute equal to the value of the entrie_name
        parameter

        :param entrie_name: The name of the object class you want to search for
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(objectClass={entrie_name})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")

    def search_user(self, username):
        """
        It searches for a user in the LDAP directory

        :param username: The username to search for
        """
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(&(objectclass=user)(cn={username}*))',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*', 'unicodePwd', 'userAccountControl'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")
            return None
        return self.conn.entries

    def get_users_from_mutliple_organisation(self, search_user: str, organisation_cn: List[str]):
        """
        It searches for all entries corresponding to the search_user parameter in the subtree of
        all the organisation in the organisation_cn list
        :param search_user: The user to search for
        :param organisation_cn: The list of organisation to search in
        :return: A list of all the users found
        """
        users = []
        for organisation in organisation_cn:
            self.conn.search(search_base=organisation,
                             search_filter=f'(&(objectclass=user)(cn={search_user}*))',
                             search_scope=ldap3.SUBTREE,
                             attributes=['*', 'unicodePwd', 'userAccountControl'])

            # Affichage du résultat de la recherche
            if not self.conn.entries:
                print("Aucune entrée trouvée")
            else:
                users.extend(self.conn.entries)
        return users

    def get_all_users(self, search_base):
        """
        It searches for all entries in the subtree of the organisation_name organisation, and prints them

        :param search_base: The base of the search
        """
        self.conn.search(search_base=search_base,
                         search_filter='(objectClass=user)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*', 'unicodePwd', 'userAccountControl'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")
        return self.conn.entries

    def set_user_birthday(self, username, birthday):
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(&(objectclass=user)(cn={username}*))',
                         search_scope=ldap3.SUBTREE,
                         attributes=['birthDate'])
        if self.conn.entries:
            user_dn = self.conn.entries[0].entry_dn
            changes = {'birthDate': [(ldap3.MODIFY_REPLACE, [birthday])]}
            self.conn.modify(user_dn, changes)
            print(f"Successfully set uBirthday {birthday} attribute for user {username}")
        else:
            print(f"User {username} not found in Active Directory")

    def getAdmUsers(self):
        """
        Get all the users in Grp_AdmAD
        :return: list of users
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(cn=Grp_AdmAD)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['member'])
        if self.conn.entries:
            users = []
            for user in self.conn.entries[0].member.values:
                users.append(self.search_user(user.split(',')[0].split('=')[1])[0].sAMAccountName.value)
            return users
        print("No users found in Grp_AdmAD")
        return []

    def get_all_groups(self):
        """
        It search all groups in the LDAP directory
        :return: list of groups
        """
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(objectClass=group)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*'])
        if self.conn.entries:
            groups = []
            for group in self.conn.entries:
                groups.append(group.cn.value)
            return groups
        print("No groups found")
        return []

    def delete_group(self, group):
        """
        Delete a group from the LDAP directory
        :param group: The group to delete
        :return: True if the group has been deleted, False otherwise
        """
        entry_dn = self.found_group(group)
        if entry_dn:
            self.conn.delete(entry_dn)
            return True
        return False

    def check_password(self, username, password):
        """
        Check if the password is correct for the username.
        :param username: The username
        :param password: The password
        :return: True if the password is correct, False otherwise
        """
        # found the user
        try:
            entries = self.search_user(username.split('_')[1] + " " + username.split('_')[0])
        except IndexError:
            entries = self.search_user(username)
        if self.conn.entries:
            password = f"b'{password}'"
            return entries[0].sAMAccountName.value == username and \
                str(entries[0].userPassword.value) == password
        return False

    def delete_users_from_group(self, users, group):
        """
        Delete a user from a group
        :param users: List of users to delete
        :param group: The group
        :return: True if the user has been deleted, False otherwise
        """
        entry_dn = self.found_group(group)
        if entry_dn:
            print(entry_dn)
            for user in users:
                u = self.search_user(user)
                if u:
                    print("user found")
                    changes = {'member': [(ldap3.MODIFY_DELETE, [u[0].entry_dn])]}
                    self.conn.modify(entry_dn, changes)
                    print(f"Successfully deleted user {user} from group {group}")
                else:
                    print(f"User {user} not found")
            return True
        print(f"Group {group} not found")
        return False


def main():
    ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', 'administrateur', 'IUT!2023')
    ldap.connection()
    print(ldap.search_user('Claire Shugg'))
    # print(ldap.getAdmUsers())
    # print(ldap.get_organiation_unit_by_name('Présidence'))
    # print(ldap.search_user('Lutero'))
    # ldap.get_all_users('SINTADirection')
    # print(ldap.get_all_users("OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN"))
    # ldap.search_group('PDG')

    # innman = Ldap('10.22.32.7', 'SINTA', 'LAN', 'innman_lutero', 'StMkiafmwQ2')
    # print(innman.connection())

    # function(ldap)
    # print("---------------------")
    # ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', 'shugg claire', 'j5q2qPDD1yQ')
    # ldap.connection()


if __name__ == '__main__':
    main()
