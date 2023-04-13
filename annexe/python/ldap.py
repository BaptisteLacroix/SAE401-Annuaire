from typing import Optional

import bcrypt
import ldap3


# It creates a connection to the LDAP server, and allows you to create
# organisations, groups and users, as well as search for them
class Ldap:
    """
    A class for connecting to an LDAP server and performing user authentication.
    """

    def __init__(self, server, dc_name, dc_org, user, password):
        """
        Initialize the LDAP connection with the provided parameters.

        :param server: The LDAP server hostname or IP address.
        :type server: str
        :param dc_name: The name of the domain controller.
        :type dc_name: str
        :param dc_org: The name of the domain organization.
        :type dc_org: str
        :param user: The username used to connect to the LDAP server.
        :type user: str
        :param password: The password used to connect to the LDAP server.
        :type password: str
        """
        self.user = user
        self.password = password
        self.conn = None
        self.server = server
        self.dc_name = dc_name
        self.dc_org = dc_org

    def __del__(self):
        """
        Close the LDAP connection.

        :return: None
        """
        # Fermeture de la connexion à l'annuaire
        print("Fermeture de la connexion")
        self.conn.unbind()

    def connection(self) -> bool:
        """
        Create a connection to the Active Directory server.

        :return: True if the connection is successful, False otherwise.
        :rtype: bool
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

    def create_organisation(self, organisation_name: str) -> None:
        """
        Create an organizational unit with the specified name in the Active Directory.

        :param organisation_name: The name of the organizational unit to create.
        :type organisation_name: str
        :return: None
        :rtype: None
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

    def create_user(self, first_name: str, last_name: str, email: str, password: str, birthday: str, tel_prof: str,
                    tel_perso: str, title: str, adresse: str, region: str, code_postal: str, ville: str, pays: str,
                    departement: str, group: str) -> bool:
        # search the department dn (Organizational Unit)
        department_dn = self.get_organiation_unit_by_name(departement)
        group_dn = self.get_group_by_name(group)

        user_dn = f"cn={first_name} {last_name},{department_dn}"

        # change birthdate format from mm/dd/yyyy to dd/mm/yyyy
        birthday = birthday.split('-')
        birthday = birthday[1] + '/' + birthday[0] + '/' + birthday[2]

        salt = bcrypt.gensalt()  # generate a random salt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'name': first_name + ' ' + last_name,
            'givenName': first_name,
            'sn': last_name,
            'mail': email,
            # set password hash
            'userPassword': hashed_password,
            'birthDate': birthday,
            'telephoneNumber': tel_prof,
            'mobile': tel_perso,
            'title': title,
            'streetAddress': adresse,
            'sAMAccountName': last_name + '_' + first_name,
            'userPrincipalName': last_name + '_' + first_name + '@SINTA.LAN',
            'st': region,
            'postalCode': code_postal,
            'l': ville,
            'co': pays,
            'company': 'SINTA',
            'displayName': first_name + ' ' + last_name,
            'distinguishedName': user_dn,
        }
        # Ajouter l'utilisateur à l'Active Directory
        self.conn.add(user_dn, attributes=attributes)

        # add user to group
        print(f"Adding user {user_dn} to group {group_dn}...")
        try:
            self.add_user_to_group([first_name + ' ' + last_name], group)
        except ldap3.core.exceptions.LDAPException as e:
            print(f"Error while adding user to group: {e}")
            return False

        # Vérifier si l'ajout a réussi
        if self.conn.result['result'] == 0:
            print("Utilisateur ajouté avec succès")
            # show where the object was created
            return True
        else:
            print("Echec de l'ajout de l'utilisateur")
            return False

    def get_organiation_unit_by_name(self, organisation_name: str) -> Optional[str]:
        """
        Search for an organization unit with the specified name in the LDAP directory and return its distinguished name.

        :param organisation_name: The name of the organization unit to search for.
        :type organisation_name: str
        :return: The distinguished name of the organization unit, or None if no such organization unit was found.
        :rtype: Optional[str]
        """
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(ou={organisation_name})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['ou'])

        if self.conn.entries:
            return self.conn.entries[0].entry_dn
        return None

    def get_group_by_name(self, group_name: str) -> Optional[str]:
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(cn={group_name})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['cn'])

        if self.conn.entries:
            return self.conn.entries[0].entry_dn
        return None

    def create_group(self, organisation_name: str, group_name: str) -> bool:
        """
        Create a new group in an organization unit.

        If the organization unit does not exist, print an error message and return.

        :param organisation_name: The name of the organization unit.
        :type organisation_name: str
        :param group_name: The name of the new group.
        :type group_name: str
        :return: None
        """
        # Données du groupe

        # Found the organisation_name and get the DN
        organisation_dn = self.get_organiation_unit_by_name(organisation_name)
        if organisation_dn is None:
            print("L'unité d'organisation n'existe pas")
            return False

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
            return True
        else:
            print("Echec de l'ajout du groupe")
            return False

    def found_group(self, group: str) -> Optional[str]:
        """
        Search for a group in the LDAP directory.

        :param group: The name of the group to search for.
        :type group: str

        :return: The distinguished name of the group if it exists, None otherwise.
        :rtype: Optional[str]
        """
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(cn={group})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['cn'])

        if self.conn.entries:
            return self.conn.entries[0].entry_dn
        return None

    def add_user_to_group(self, users_display_name: list[str], group_name: str) -> bool:
        """
        Add a list of users to a group in Active Directory.

        Searches for the group and each user by display name, then adds the users to the group.
        Prints a success message for each user added to the group, or an error message if the user or group is not found.

        :param users_display_name: A list of display names for the users to add to the group.
        :type users_display_name: list[str]
        :param group_name: The name of the group to add the users to.
        :type group_name: str
        :return: True if the users were added to the group, False otherwise.
        :rtype: bool
        """
        results = False
        # Ajout de l'utilisateur au groupe
        group_cn = self.found_group(group_name)
        if group_cn is None:
            print("Le groupe n'existe pas")
            return False

        # for each user
        for user in users_display_name:
            user_cn = self.search_user(user)
            if user_cn is None:
                print("L'utilisateur n'existe pas")
                return False
            self.conn.extend.microsoft.add_members_to_groups(
                f'{user_cn[0].distinguishedName.value}',
                [f'{group_cn}'])

            # Vérification de la réussite de l'ajout
            if self.conn.result['result'] == 0:
                print(f"Utilisateur {user} ajouté au groupe {group_name} avec succès")
                results = True
            else:
                print("Echec de l'ajout de l'utilisateur au groupe")
        return results

    def get_all_organisation_unit(self) -> list[str]:
        """
        Retrieve a list of all organizational units (OUs) from the LDAP directory.

        :return: A list of OUs if any are found, an empty list otherwise.
        :rtype: List[str]
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter='(objectClass=organizationalUnit)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['ou'])

        if not self.conn.entries:
            return []
        return [entry.ou.value for entry in self.conn.entries]

    def search_user(self, username: str) -> Optional[list[ldap3.Entry]]:
        """
        Search for a user with the specified username in the LDAP directory.

        :param username: The username to search for.
        :type username: str
        :return: A list of LDAP entries corresponding to the search results, or None if no entries are found.
        :rtype: Optional[List[ldap3.Entry]]
        """
        try:
            self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                             search_filter=f'(&(objectclass=user)(cn={username}*))',
                             search_scope=ldap3.SUBTREE,
                             attributes=['*', 'unicodePwd', 'userAccountControl'])
            # Affichage du résultat de la recherche
            if not self.conn.entries:
                print("Aucune entrée trouvée")
                return None
            return self.conn.entries
        except TypeError:
            return None

    def get_users_from_mutliple_organisation(self, search_user: str, organisation_cn: list[str]) -> list[ldap3.Entry]:
        """
        Search for users in multiple organisations with the specified common name (cn).

        :param search_user: The username or a partial username to search for.
                            Use '*' as a wildcard to search for all users.
        :type search_user: str
        :param organisation_cn: A list of common names (cn) of the organisations to search in.
        :type organisation_cn: list[str]
        :return: A list of LDAP entries representing the users that match the search criteria.
        :rtype: list[ldap3.Entry]
        """
        if search_user == "*":
            search_user = '*'
        # else if search_user does not contain '*' add it at the end and at the beginning*
        elif '*' not in search_user:
            search_user = f'*{search_user}*'
        else:
            search_user = f'{search_user}'
        try:
            users = []
            for organisation in organisation_cn:
                self.conn.search(search_base=organisation,
                                 search_filter=f'(&(objectclass=user)(cn={search_user}))',
                                 search_scope=ldap3.SUBTREE,
                                 attributes=['*', 'userAccountControl'])
                # Affichage du résultat de la recherche
                if self.conn.entries:
                    users.extend(self.conn.entries)
            return users
        except TypeError:
            return []

    def get_all_users(self, search_base: str) -> list[ldap3.Entry]:
        """
        Retrieve all user entries under the specified search base.

        :param search_base: The LDAP search base to use.
        :type search_base: str
        :return: A list of user entries.
        :rtype: list[ldap3.Entry]
        """
        self.conn.search(search_base=search_base,
                         search_filter='(objectClass=user)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*', 'userAccountControl'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")
        return self.conn.entries

    def get_multiple_users(self, users: list[str]) -> list[ldap3.Entry]:
        """
        Retrieve the LDAP entries for multiple users.

        For each username in the `users` list, call `search_user()` to retrieve the corresponding LDAP entry.
        If an LDAP entry is found for a given username, append it to a list of entries.
        Return the list of entries for all users that had an LDAP entry.

        :param users: A list of usernames to retrieve LDAP entries for.
        :type users: list[str]
        :return: A list of LDAP entries for the specified users.
        :rtype: list[ldap3.Entry]
        """
        entries = []
        for user in users:
            return_value = self.search_user(user)
            if return_value is not None:
                entries.extend(return_value)
        return entries

    def get_mutliple_users_from_multiple_organisation(self, users: list[str], organisation_cn: list[str]) -> list[
        ldap3.Entry]:
        """
        Return a list of LDAP entries for multiple users in multiple organizations.

        For each user in the `users` list, search for their LDAP entry in each organization
        specified in the `organisation_cn` list. If the user is found in an organization,
        add their entry to the list of entries to return.

        :param users: A list of user IDs to search for.
        :type users: list[str]
        :param organisation_cn: A list of organization common names to search in.
        :type organisation_cn: list[str]
        :return: A list of LDAP entries for the specified users in the specified organizations.
        :rtype: list[ldap3.Entry]
        """
        entries = []
        for user in users:
            return_value = self.get_users_from_mutliple_organisation(user, organisation_cn)
            if return_value is not None:
                entries.extend(return_value)
        return entries

    def set_user_birthday(self, username: str, birthday: str) -> None:
        """
        Set the 'birthDate' attribute of the given user in the Active Directory to the specified value.

        :param username: The username of the user whose 'birthDate' attribute should be set.
        :type username: str
        :param birthday: The new value of the 'birthDate' attribute.
        :type birthday: str
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(&(objectclass=user)(cn={username}))',
                         search_scope=ldap3.SUBTREE,
                         attributes=['birthDate'])
        if self.conn.entries:
            user_dn = self.conn.entries[0].entry_dn
            changes = {'birthDate': [(ldap3.MODIFY_REPLACE, [birthday])]}
            self.conn.modify(user_dn, changes)
            print(f"Successfully set uBirthday {birthday} attribute for user {username}")
        else:
            print(f"User {username} not found in Active Directory")

    def get_adm_users(self) -> list[str]:
        """
        Retrieve the list of usernames of all users in the 'Grp_AdmAD' group.

        :return: A list of usernames.
        :rtype: List[str]
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter='(cn=Grp_AdmAD)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['member'])
        if self.conn.entries:
            users = []
            for user in self.conn.entries[0].member.values:
                users.append(self.search_user(user.split(',')[0].split('=')[1])[0].sAMAccountName.value)
            return users
        print("No users found in Grp_AdmAD")
        return []

    def get_all_groups(self) -> list[str]:
        """
        Retrieve a list of all groups in the Active Directory.

        Searches the Active Directory for all objects of class 'group' under the 'OU=Société SINTA' Organizational Unit.
        Returns a list of the Common Name (cn) attribute values of each group object.

        :return: A list of group names, or an empty list if no groups are found.
        :rtype: List[str]
        """
        self.conn.search(search_base=f'OU=Société SINTA,dc={self.dc_name},dc={self.dc_org}',
                         search_filter='(objectClass=group)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*'])
        if self.conn.entries:
            groups = []
            for group in self.conn.entries:
                groups.append(group.cn.value)
            return groups
        print("No groups found")
        return []

    def delete_group(self, group: str) -> bool:
        """
        Delete a group from the LDAP server.

        :param group: The name of the group to delete.
        :type group: str
        :return: True if the group was successfully deleted, False otherwise.
        :rtype: bool
        """
        entry_dn = self.found_group(group)
        if entry_dn:
            self.conn.delete(entry_dn)
            return True
        return False

    def check_password(self, username: str, password: str) -> bool:
        """
        Check if the given password matches the password for the given username in the LDAP directory.

        :param username: The username to check the password for.
        :type username: str
        :param password: The password to check.
        :type password: str
        :return: True if the password is correct, False otherwise.
        :rtype: bool
        """
        # found the user
        try:
            entries = self.search_user(username.split('_')[1] + " " + username.split('_')[0])
        except IndexError:
            entries = self.search_user(username)
        if self.conn.entries:
            return entries[0].sAMAccountName.value == username and \
                bcrypt.checkpw(password.encode('utf-8'), bytes(entries[0].userPassword.value))
        return False

    def delete_users_from_group(self, users: list[str], group: str) -> bool:
        """
        Remove a list of users from a group in the LDAP directory.

        :param users: A list of usernames to remove from the group.
        :type users: list[str]
        :param group: The name of the group to remove the users from.
        :type group: str
        :return: True if all users were successfully removed from the group, False otherwise.
        :rtype: bool
        """
        entry_dn = self.found_group(group)
        if entry_dn:
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

    def delete_users(self, user):
        """
        Delete a user from the LDAP server.

        :param user: The name of the user to delete.
        :type user: str
        :return: True if the user was successfully deleted, False otherwise.
        :rtype: bool
        """
        entry_dn = self.search_user(user)
        if entry_dn:
            self.conn.delete(entry_dn[0].entry_dn)
            return True
        return False


def main():
    ldap = Ldap('10.22.32.7', 'SINTA', 'LAN', 'administrateur', 'IUT!2023')
    ldap.connection()
    print(ldap.search_user('Claire Shugg'))
    # print(ldap.search_user('Harlin Tadlow'))
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
