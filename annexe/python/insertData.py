import ldap3
import pandas as pd
from ldap3 import Server, Connection, ALL, MODIFY_ADD, SUBTREE, MODIFY_REPLACE


def create_user(conn: ldap3.Connection, df: pd.DataFrame) -> None:
    """
    Create new users in the Active Directory based on the data in a Pandas DataFrame.

    For each row in the DataFrame, create a new user with the specified attributes, and add them to the appropriate groups.
    If the user is part of the {Grp_AdmAD} group (based on the "Form_base" column), add them to the Admin group as well.
    Print a message for each user that is successfully added to the Active Directory.

    :param conn: An LDAP connection to the Active Directory.
    :type conn: ldap3.Connection
    :param df: A Pandas DataFrame containing the user data to be added to the Active Directory.
    :type df: pd.DataFrame
    :return: None
    """
    for _, row in df.iterrows():
        dn = f"cn={row['first_name']} {row['last_name']},OU={row['Département']},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN"

        password = row['password']
        # hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'name': row['first_name'] + ' ' + row['last_name'],
            'givenName': row['first_name'],
            'sn': row['last_name'],
            'mail': row['e-mail'],
            # set password as sha256 hash
            'userPassword': password,
            'birthDate': row['birthday'].strftime('%Y/%m/%d'),
            'telephoneNumber': str(row['tel_prof']),
            'mobile': str(row['tel-perso']),
            'title': row['Title'],
            'streetAddress': row['adresse'],
            'sAMAccountName': row['last_name'] + '_' + row['first_name'],
            'userPrincipalName': row['last_name'] + '_' + row['first_name'] + '@SINTA.LAN',
            'st': row['region'],
            'postalCode': str(row['code_postal']),
            'l': row['ville'],
            'co': row['pays'],
            'company': 'SINTA',
            'displayName': row['first_name'] + ' ' + row['last_name'],
            'distinguishedName': f'CN={row["first_name"]} {row["last_name"]},OU={row["Département"]},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
        }
        # Ajouter l'utilisateur à l'Active Directory
        conn.add(dn, attributes=attributes)

        # show where the users are added
        print("\n\nAjout utilisateur : ", conn.result)

        # create the group
        create_group(conn, row)

        # add the user to the group
        add_user_to_group(conn, row)

        if str(row["Form_base"]) == str(0) or str(row["Form_base"]) == str(1):
            # add the user to the group {Grp_AdmAD}
            add_to_admin_group(conn, row)

        print(f"User {row['first_name']} {row['last_name']} added to Active Directory with password {row['password']}")


def add_to_admin_group(conn: Connection, row: dict[str, str]) -> None:
    """
    Add a user to the Grp_AdmAD group in the Active Directory.

    If the Grp_AdmAD group does not exist, create it.
    Search for the user with the specified first and last names.
    Add the user to the Grp_AdmAD group.

    :param conn: A Connection object representing the LDAP connection.
    :type conn: Connection
    :param row: A dictionary containing the user's attributes, including 'first_name', 'last_name', and 'Département'.
    :type row: Dict[str, str]
    :return: None
    """
    # search the group {Grp_AdmAD} in the Active Directory
    conn.search(
        search_base='OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
        search_filter=f'(cn=Grp_AdmAD)',
        search_scope='SUBTREE',
        attributes=['cn', 'distinguishedName']
    )

    if len(conn.entries) <= 0:
        create_admin_group(conn)

    # search the user with the first_name attribute["first_name"] and last_name attribute["last_name"]
    conn.search(search_base=f'OU={row["Département"]},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
                search_filter=f'(&(objectclass=user)(cn={row["first_name"]} {row["last_name"]}*))',
                search_scope=SUBTREE,
                attributes=['distinguishedName'])

    user_dn = str(conn.entries[0].distinguishedName)

    # add the user to the group {Grp_AdmAD}
    conn.modify(f'cn=Grp_AdmAD,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
                {'member': [(MODIFY_ADD, [user_dn])]})
    # show where the users are added
    print("ajout utilisateur ADMINNNN dans groupe : ", conn.result['result'])


def create_admin_group(conn: ldap3.Connection) -> None:
    """
    Create an administrative group in the Active Directory and grant it administrative privileges.

    The group is named 'Grp_AdmAD' and is created in the 'SINTADirection' organizational unit of the 'Société SINTA'
    domain. The group is granted the 'admin' privileges, allowing its members to manage the Active Directory.

    :param conn: The LDAP connection to use for the operation.
    :type conn: ldap3.Connection
    :return: None
    :rtype: None
    """
    # create a group in SINTADirection name as Grp_AdmAD
    group_dn = f'cn=Grp_AdmAD,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN'
    # make this group with the admin privileges the users in this group will, can manage the Active Directory
    group_attributes = {'objectClass': ['top', 'group'], 'cn': 'Grp_AdmAD', 'groupType': '-2147483646'}
    conn.add(group_dn, attributes=group_attributes)
    admin_group_dn = 'cn=Administrateurs,cn=Builtin,dc=SINTA,dc=LAN'
    conn.modify(admin_group_dn, {'member': [(MODIFY_ADD, [group_dn])]})
    control_access_rule = 'CN=Domain Controllers,CN=Users,DC=SINTA,DC=LAN;user'
    conn.modify(group_dn, {'ntSecurityDescriptor': [(MODIFY_REPLACE, ['D:(A;;RP;;;' + control_access_rule + ')'])]})
    # Check that the group was added to the Administrators group
    conn.search(admin_group_dn, '(objectClass=*)', attributes=['member'])
    print(conn.entries[0].member)


def create_group(conn: Connection, row: dict[str, str]) -> None:
    """
    Create a group in the Active Directory and add the user to the group.

    If the group {Département} does not exist in the Active Directory, create it with the name from the given row.
    Add the user to the group.

    :param conn: An LDAP connection object.
    :type conn: ldap3.Connection
    :param row: A dictionary containing the values for the group.
    :type row: Dict[str, str]
    """
    # search the group {Département} in the Active Directory
    conn.search(
        search_base='OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
        search_filter=f'(cn={row["Département"]})',
        search_scope='SUBTREE',
        attributes=['cn', 'distinguishedName']
    )

    if len(conn.entries) <= 0:  # create the group {Département} and add the user to the group
        group_dn = f'cn={row["Département"]},OU={row["Département"]},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN'
        group_attributes = {
            'objectClass': ['top', 'group'],
            'cn': row['Département'],
            'distinguishedName': f'CN={row["Département"]},OU={row["Département"]},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
        }
        conn.add(group_dn, attributes=group_attributes)
        # show where the users are added
        print("Ajout groupe : ", conn.result['result'])


def add_user_to_group(conn: ldap3.Connection, row: dict) -> None:
    """
    Add a user to a group in Active Directory.

    The user is identified by their first and last names, which are used to search for their distinguished name (DN).
    The group is identified by its name and the department to which it belongs.

    :param conn: An LDAP connection object.
    :type conn: ldap3.Connection
    :param row: A dictionary containing information about the user and the group.
                It must have the following keys:
                    - "first_name": the user's first name.
                    - "last_name": the user's last name.
                    - "Département": the name of the department to which the group belongs.
    :type row: dict
    :return: None
    """
    # search the user with the first_name attribute["first_name"] and last_name attribute["last_name"]
    conn.search(search_base=f'OU={row["Département"]},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
                search_filter=f'(&(objectclass=user)(cn={row["first_name"]} {row["last_name"]}*))',
                search_scope=SUBTREE,
                attributes=['distinguishedName'])

    user_dn = str(conn.entries[0].distinguishedName)

    # add the user to the group
    group_dn = f'cn={row["Département"]},OU={row["Département"]},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN'
    conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
    # show where the users are added
    print("ajout utilisateur dans groupe : ", conn.result['result'])


def create_organisation_unit(conn: ldap3.Connection) -> None:
    """
    Create organizational units in the LDAP directory.

    The organizational units are created using the provided LDAP connection object, conn. The names and structure of
    the organizational units are hard-coded in the function.

    :param conn: The LDAP connection object to use.
    :type conn: ldap3.Connectino
    :return: None
    :rtype: None
    """
    all_filters = [
        "OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=Département Assistance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=Département Communication,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=Département Finance,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=Département Informatique,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=Département Marketing,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=Département Ressources Humaines,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
        "OU=Présidence,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN",
    ]

    # Creation des Unités Organisatrices
    for f in all_filters:
        conn.add(f, ['organizationalUnit'])
        # show where the users are added
        print("Ajout organisation Unit : ", conn.result['result'])


def main():
    # Paramètres de connexion à l'Active Directory
    ldap_server = '10.22.32.7'
    ldap_username = 'cn=administrateur,cn=users,dc=SINTA,dc=LAN'
    ldap_password = 'IUT!2023'

    # Charger les données à partir du fichier xlsx
    filename = 'users.xlsx'
    df = pd.read_excel(filename, engine='openpyxl')

    # Connexion au serveur Active Directory
    server = Server(ldap_server, get_info=ALL)
    conn = Connection(server, ldap_username, ldap_password, auto_bind=True)

    create_organisation_unit(conn)
    create_user(conn, df)

    # Fermer la connexion
    conn.unbind()


if __name__ == '__main__':
    main()
