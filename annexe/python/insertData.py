import pandas as pd
from ldap3 import Server, Connection, ALL, MODIFY_ADD, SUBTREE


def create_user(conn, df):
    for _, row in df.iterrows():
        dn = f"cn={row['first_name']} {row['last_name']},OU={row['Département']},OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN"

        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'name': row['first_name'] + ' ' + row['last_name'],
            'givenName': row['first_name'],
            'sn': row['last_name'],
            'mail': row['e-mail'],
            'userPassword': row['password'],
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
        print("\n\nAjout utilisateur : ", conn.result['result'])

        # create the group
        create_group(conn, row)

        # add the user to the group
        add_user_to_group(conn, row)

        if str(row["Form_base"]) == str(0) or str(row["Form_base"]) == str(1):
            # add the user to the group {Grp_AdmAD}
            add_to_admin_group(conn, row)

        print(f"User {row['first_name']} {row['last_name']} added to Active Directory with password {row['password']}")


def add_to_admin_group(conn, row):
    # search the group {Grp_AdmAD} in the Active Directory
    conn.search(
        search_base='OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN',
        search_filter=f'(cn=Grp_AdmAD)',
        search_scope='SUBTREE',
        attributes=['cn', 'distinguishedName']
    )

    if len(conn.entries) <= 0:
        # create a group in SINTADirection name as Grp_AdmAD
        group_dn = f'cn=Grp_AdmAD,OU=SINTADirection,OU=Société SINTA,DC=SINTA,DC=LAN'
        # make this group with the admin privileges the users in this group will, can manage the Active Directory
        group_attributes = {'objectClass': ['top', 'group'], 'cn': 'Grp_AdmAD', 'groupType': '-2147483646'}
        conn.add(group_dn, attributes=group_attributes)
    else:

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


def create_group(conn, row):
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
        print("Ajout groupe : ", conn.result)


def add_user_to_group(conn, row):
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


def create_organisation_unit(conn):
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
