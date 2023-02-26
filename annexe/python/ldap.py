import ldap3
import pandas as pd
from pandas._libs import json


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

    def logout(self):
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

    def create_group(self, organisation_name, group_name):
        """
        It creates a group in the specified organisation

        :param organisation_name: The name of the organisation to which the group belongs
        :param group_name: The name of the group you want to create
        """
        # Données du groupe
        group_dn = f'cn={group_name},ou={organisation_name},dc={self.dc_name},dc={self.dc_org}'
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

    def create_user(self, organisation_name, last_name, first_name,
                    email, password, birth_date, private_phone, professional_phone, title,
                    address, group_name):
        """
        It creates a user in the Active Directory

        :param organisation_name: The name of the organisation
        :param last_name: The user's last name
        :param first_name: The first name of the user
        :param email: The email address of the user
        :param password: The password for the user
        :param birth_date: The date of birth of the user
        :param private_phone: The user's private phone number
        :param professional_phone: The user's professional phone number
        :param title: The title of the user
        :param address: The user's street address
        :param group_name: The name of the group you want to add the user to
        """
        # Données de l'utilisateur
        user_dn = f'cn={last_name} {first_name},ou={organisation_name},dc={self.dc_name},dc={self.dc_org}'

        user_attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': last_name + ' ' + first_name,
            'sn': last_name,
            'givenName': first_name,
            'mail': email,
            'userPassword': password,
            'uBirthday': birth_date,
            'telephoneNumber': professional_phone,
            'homePhone': private_phone,
            'title': title,
            'streetAddress': address,
            'SamAccountName': last_name + '.' + first_name
        }

        # Ajout de l'utilisateur
        self.conn.add(user_dn, attributes=user_attributes)

        # Vérification de la réussite de l'ajout
        if self.conn.result['result'] == 0:
            print("Utilisateur ajouté avec succès")
        else:
            print("Echec de l'ajout de l'utilisateur")
            # show the problem
            print(self.conn.result)

        self.add_user_to_group(last_name, first_name, organisation_name, group_name)

    def add_user_to_group(self, last_name, first_name, organisation_name, group_name):
        """
        It adds a user to a group

        :param last_name: The last name of the user
        :param first_name: The first name of the user
        :param organisation_name: The name of the organisation
        :param group_name: The name of the group to add the user to
        """
        # Ajout de l'utilisateur au groupe
        self.conn.extend.microsoft.add_members_to_groups(
            f'cn={last_name} {first_name},ou={organisation_name},dc={self.dc_name},dc={self.dc_org}',
            [f'cn={group_name},ou={organisation_name},dc={self.dc_name},dc={self.dc_org}'])

        # Vérification de la réussite de l'ajout
        if self.conn.result['result'] == 0:
            print("Utilisateur ajouté au groupe avec succès")
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
        for entry in self.conn.entries:
            print(entry)

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
        for entry in self.conn.entries:
            print(entry)

    def search_user(self, username):
        """
        It searches for a user in the LDAP directory

        :param username: The username to search for
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(cn={username})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*', 'unicodePwd', 'userAccountControl'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")
        for entry in self.conn.entries:
            print(entry)
            if 'unicodePwd' in entry:
                print(f"User password: {entry['unicodePwd']}")
        return self.conn.entries

    def search_group(self, group_name):
        """
        It searches for a group in the LDAP directory

        :param group_name: The name of the group you want to search for
        """
        self.conn.search(search_base=f'dc={self.dc_name},dc={self.dc_org}',
                         search_filter=f'(cn={group_name})',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")
        for entry in self.conn.entries:
            print(entry)

    def get_all_users(self, organisation_name):
        """
        It searches for all entries in the subtree of the organisation_name organisation, and prints them

        :param organisation_name: The name of the organisation you want to search in
        """
        self.conn.search(search_base=f'ou={organisation_name},dc={self.dc_name},dc={self.dc_org}',
                         search_filter='(objectClass=user)',
                         search_scope=ldap3.SUBTREE,
                         attributes=['*', 'unicodePwd', 'userAccountControl'])

        # Affichage du résultat de la recherche
        if not self.conn.entries:
            print("Aucune entrée trouvée")
        for entry in self.conn.entries:
            print(entry)
            if 'unicodePwd' in entry:
                print(f"User password: {entry['unicodePwd']}")
        return self.conn.entries

    # DO an anction as user


def function():
    # Open the CSV file and read its contents
    data = pd.read_csv('users.csv', sep=';', encoding='utf-8')
    # Create an empty dictionary to store the organizational hierarchy
    hierarchy = {}

    # Group the data by Form_base and iterate over each group
    for form_base, group in data.groupby('Form_base'):
        # Create a dictionary to store the positions for the current Form_base
        positions = {}

        # Iterate over each row in the group and add the position to the positions dictionary
        for index, row in group.iterrows():
            # Get the position and its parent position
            position = row['Title']
            parent_position = row['Supérieur_hiérarchique']

            # If the parent position is NaN, set it to the current Form_base
            if pd.isna(parent_position):
                parent_position = form_base

            # Get the parent dictionary for the current position
            parent_dict = positions.get(parent_position, positions)

            # Create a dictionary for the current position
            position_dict = parent_dict.setdefault(position, {})

            # Add the position to the positions dictionary
            positions[position] = position_dict

        # Add the positions dictionary to the hierarchy for the current Form_base
        hierarchy[form_base] = positions

    # Print the hierarchy
    print(hierarchy)
    print(json.dumps(hierarchy, indent=4, ensure_ascii=False))


def main():
    organisation_name = 'Société SINTA'
    ldap = Ldap('10.22.32.3', 'SINTA', 'LAN', 'administrateur', 'IUT!2023')
    ldap.connection()
    #ldap.search_user('Lutero Innman')
    ldap.search_user('Claire Shugg')
    # ldap.get_all_users('Société SINTA')
    # ldap.search_group('PDG')

    # innman = Ldap('10.22.32.3', 'SINTA', 'LAN', 'innman_lutero', 'StMkiafmwQ2')
    # print(innman.connection())

    # function()


if __name__ == '__main__':
    main()

"""
PDG
    Responsable Communication
         Chargé de communication réseaux sociaux
         Chargé de publicité
         Chargé de presse
         Chargé de contenue
    Directeur des Ressources Humaines
         Chargé de recrutement
         Chargé de formation
         Gestionnaire des RH
    Responsable assistance
         Chargé d'assistance téléphonique
         Chargé d'assistance web
         Assistant administratif
         Support client
    Responsable Informatique
         Responsable de l'administration réseau
         Gestionnaire de base de données
         Responsable de développement web
         Analyste de données graphiques
    Directrice financière
         Comptable
         Trésorerie
         Analyste financier
         Contrôle de gestion
    Directrice marketing
         Analyste marketing
         Chargé de produit
         Responsable du branding
"""
