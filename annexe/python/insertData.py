import pandas as pd
from ldap3 import Server, Connection, ALL

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
    print(conn.result)

    print(f"User {row['first_name']} {row['last_name']} added to Active Directory with password {row['password']}")

# Fermer la connexion
conn.unbind()
