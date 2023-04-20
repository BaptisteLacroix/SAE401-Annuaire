# Project Name: Active Directory Lookup

# Objective
The main objective of this project is to design an application that allows interaction with an Active Directory. The project aims to create a website that enables us to perform searches to gather information about employees within our company.

# General Objectives
As a technical team, we aim to:

 - Configure the Active Directory
 - Create a website to use the Active Directory of the company
 - Manage the database (creating/deleting groups and adding/removing employees from a group)
 - Keep the user database up to date (creating/deleting employees)
 - Establish a connection between the website and the database
 - Feed the active directory through a script
 
As a user, they can:

 - Perform precise searches or use jokers
 - Consult information about the person searched for (name, first name, professional email, department, role, professional phone  number, company)
 - Connect as an administrator (Grp_AdmAD) to access more information during the search
 - Consult the help for the search on the homepage
 - Translate the page based on the chosen language
 
# Main Features
## Hierarchy
 - Search for employee names
 - Search using jokers
 - Access the information of the employee searched for
 - Keep the groups up to date by the administrator
 
# Definitions
 1. The search function allows finding an employee using simple search. For example: "Fabien" will return all employees with the first or last name "Fabien".<br>The functionality using jokers allows searching for an employee using the "`*`" character. For example: "`Fa*en`" will return all employees with the first letters "Fa" and last letters "en".
 2. This feature allows displaying information about the searched employee, such as their name, first name, email, and phone number for lambda users. More information will be available to connected users with administrative permissions.
 3. This feature will allow the site administrator to manage the database, i.e., add, modify, and consult accounts in the database.
 
#  Secondary Features
## Hierarchy
 - Filter searches
 - Search for users by date of birth (only for connected users) using jokers
 - Translate the site according to the desired language
 - Suggest search for the user
 - User administration
 
# Definitions
 - The filter search feature allows searching for an employee more precisely. Example: "Fabien" will return all employees named "Fabien", and the filter can be applied to see all "Fabien" working in the HR department.
 - The date of birth search feature using jokers (>, <, -) allows searching for a specific employee. For example, ">1999" will search for all people born after 1999, "1980-1999" will search for all people born between 1980 and 1999, "1999" will search for all people born in 1999, and finally, 10/05/1999 will search for people born on May 10, 1999.
 - This feature allows foreign users to consult the page without any problems. Three languages will be available (English, Spanish, and French).
 - The search suggestion feature enables the user to obtain recommended results after entering a few letters in the search.
 - The feature allows the administrator to create or delete users to maintain a good overview of the company on the site.
 
# Technologies Used
 - Python (Flask) for back-end development
 - JavaScript for front-end development and for the communication between the server and the front
 - HTML/CSS for creating the website interface
 - Active Directory for managing the database and user accounts
 
# Features
The main features of the application are:
 - The main features of the application are:
 - Searching employees using their name or using wildcard characters.
 - Displaying employee information such as name, email, department, role, and phone number.
 - Allowing the administrator to manage the user database, including adding, modifying, and deleting user accounts.
 - Allowing users to filter their search results based on the birthdate of employees.
 - Translating the website into three different languages: English, French, and Spanish.
 - Providing search suggestions to users after they start typing in the search bar.
Allowing the administrator to create and delete user accounts.

# Installation
To run the application locally, follow these steps:

 - Clone the project from the GitHub repository.
 - Install the required dependencies using pip : 
    - `pip install Flask`
    - `pip install regex`
    - `pip install ldap3`
 - Make sure Active Directory is installed and configured properly.
 - Run the server.py file using Python to start the Flask server.
    - `flask --app server.py run`
 - Open a web browser and navigate to http://localhost:5000 to access the website.
 - You can insert the data from the users.xlsx file into the AD using the insertData.py file.


# Contributors
This project was created by :
 - [Lacroix Baptiste](https://github.com/BaptisteLacroix)
 - [Romain Patureau](https://github.com/RainbowGamer333)
 - [Mateus Lopes](https://github.com/Cmoitchoupi)
 - [Marvin Conil](https://github.com/MarvStunt)
 - [Hassan Sacha](https://github.com/SachaHassan) <br>

During the second year of the BUT program at the University Nice Côte d'Azur, under the supervision of professors Ms. Feneon and Mr. Bilancini.
