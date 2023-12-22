# ========================================================
# = Importing Libraries
# ========================================================
# import third-party libraries
import bson
from pymongo.database import Database
from email_validator import validate_email, EmailNotValidError

# import Python's standard libraries
import re
import sys
import asyncio
import pathlib
from datetime import datetime

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "app")
sys.path.append(str(PYTHON_FILES_PATH))
from utils import constants as C # type: ignore
from utils.functions import database as mongo # type: ignore
from gcp import GcpAesGcm # type: ignore

# ========================================================
# = End of Importing libraries
# ========================================================

# TODO: Fix bugs, show print statements of successful operations
# TODO: re order the if else statements for a cleaner user interaction

# ========================================================
# = Start of Menu Printings
# ========================================================

def create_menu( 
    user_count: int | None = 0, 
    admin_count: int | None = 0,
    maintenance_count: int | None = 0, 
    report_count: int | None = 0, 
    fake_reporter_count: int | None = 0, 
    victim99_count: int | None = 0, 
    debug: bool | None = True,
) -> None:
    MENU = f"""----------- Menu ({'Debug' if debug else 'PROD'} Mode) -------------

> Note: This is only for TESTING purposes.
> Test User Count: {user_count}
> Admin User Count: {admin_count}
> Maintenance User Count: {maintenance_count}
> all Users Count: {user_count + admin_count + maintenance_count}
> All Report Count: {report_count}
> Fake Reporter Count: {fake_reporter_count}
> Victim99 Count: {victim99_count}

1. Create X number of test users
2. Create X number of professional users
3. Make Fake reports
4. Make Demo Banned Accounts

X. Close program


-------------------------------------------"""
    print(MENU)


def delete_menu(
    user_count: int | None = 0, 
    admin_count: int | None = 0,
    maintenance_count: int | None = 0, 
    report_count: int | None = 0, 
    fake_reporter_count: int | None = 0, 
    victim99_count: int | None = 0, 
    debug: bool | None = True,
) -> None:
    MENU = f"""----------- Menu ({'Debug' if debug else 'PROD'} Mode) -------------

> Note: This is only for TESTING purposes.
> Test User Count: {user_count}
> Admin User Count: {admin_count}
> Maintenance User Count: {maintenance_count}
> all Users Count: {user_count + admin_count + maintenance_count}
> All Report Count: {report_count}
> Fake Reporter Count: {fake_reporter_count}
> Victim99 Count: {victim99_count}

1. Delete all test users' data
2. Deleteb Mirai Plus Accounts
3. Delete all admin users' data
4. Delete all maintenance users' data
5. Delete all fake reports
6. Delete all demo banned accounts

X. Close program

-------------------------------------------"""
    print(MENU)

# TODO: making create users more cleaner
def oauth_menu( 
    user_count: int | None = 0, 
    admin_count: int | None = 0,
    maintenance_count: int | None = 0, 
    report_count: int | None = 0, 
    fake_reporter_count: int | None = 0, 
    victim99_count: int | None = 0, 
    debug: bool | None = True,
) -> None:
    MENU = f"""----------- Menu ({'Debug' if debug else 'PROD'} Mode) -------------

> Note: This is only for TESTING purposes.
> Test User Count: {user_count}
> Admin User Count: {admin_count}
> Maintenance User Count: {maintenance_count}
> all Users Count: {user_count + admin_count + maintenance_count }
> All Report Count: {report_count}
> Fake Reporter Count: {fake_reporter_count}
> Victim99 Count: {victim99_count}

1. Create test users
2. Create professional users
3. Create admin users
4. Create maintenace users

X. Close program


-------------------------------------------"""
    print(MENU)


def choose_menu(
    user_count: int | None = 0, 
    admin_count: int | None = 0,
    maintenance_count: int | None = 0, 
    report_count: int | None = 0, 
    fake_reporter_count: int | None = 0, 
    victim99_count: int | None = 0, 
    debug: bool | None = True,
) -> None:
    MENU = f"""----------- Menu ({'Debug' if debug else 'PROD'} Mode) -------------

> Note: This is only for TESTING purposes.
> Test User Count: {user_count}
> Admin User Count: {admin_count}
> Maintenance User Count: {maintenance_count}
> all Users Count: {user_count + admin_count + maintenance_count }
> All Report Count: {report_count}
> Fake Reporter Count: {fake_reporter_count}
> Victim99 Count: {victim99_count}

1. Create Menu
2. Delete Menu
3. use oauth to create dummy accounts

X. Close program

-------------------------------------------"""
    print(MENU)

# ========================================================
# = End of Menu Printing
# ========================================================

# ========================================================
# = Start of Functions
# ========================================================
def enter_email() -> str:
    """Validates email input and returns the validated email address."""
    while True:
        emailInput = input("Enter Email (x to cancel): ").strip().lower()
        if emailInput == "x":
            return "x"
        try:
            return validate_email(emailInput).email
        except (EmailNotValidError) as e:
            print(f"Invalid email Error: {e}", end="\n\n")
            continue

# --------------------------------------------------------
# - Variables
#---------------------------------------------------------
DEMO_PASSWORD_HASH = C.HASHER.hash("p@ssw0rd")
ADMIN_REGEX = re.compile(r"admin_\d+")
USER_REGEX = re.compile(r"user_\d+")
MAINTENANCE_REGEX = re.compile(r"maintenance_\d+")
SUPER_ROOT_REGEX = re.compile(r"superroot_\d+")
ALL_USERS_REGEX = re.compile(r"(admin|user|maintenance|superroot)_\d+")
AESGCM = GcpAesGcm()

# --------------------------------------------------------
# - Creating users Function
#---------------------------------------------------------
def create_fake_users(db: Database, acc_type: str, user_count: int | None = 5 ) -> None:
    regex = ADMIN_REGEX if acc_type == C.ADMIN else USER_REGEX
    cursor = db[C.USER_COLLECTION].find({
        "username": {
            "$regex": regex}
        }
    )

    largest_number = 1
    results = list(cursor.sort("username", -1).limit(1))
    if results:
        username: str = results[0]["username"]
        largest_number = int(username.split(sep="_", maxsplit=1)[1]) + 1

    encrypted_password = asyncio.run(
        AESGCM.symmetric_encrypt(
            plaintext=DEMO_PASSWORD_HASH,
            key_id=C.DATABASE_KEY,
        )
    )
    encrypted_password = bson.Binary(encrypted_password)
    iterator = range(largest_number, largest_number + user_count)

    if acc_type == "user":
        db[C.USER_COLLECTION].insert_many(
            mongo.get_default_user_doc(
                email=f"user_{num}@demo.com",
                username=f"user_{num}",
                display_name=f"User{num}",
                password_hash=encrypted_password,
                session_info=None,
                verified=True,
            )
        for num in iterator)
    elif acc_type == "mirai_plus":
        db[C.USER_COLLECTION].insert_many(
            mongo.get_default_user_doc(
                email=f"miraiplus{num}@demo.com",
                username=f"miraiplus_{num}",
                display_name=f"miraiplus{num}",
                password_hash=encrypted_password,
                session_info=None,
                verified=True,
                mirai_plus=True,
            ) for num in iterator)
    elif acc_type == "fake_reporter":
        db[C.USER_COLLECTION].insert_many(
            mongo.get_default_user_doc(
                email=f"fakenews{num}@demo.com",
                username=f"fakereporter_{num}",
                display_name=f"Fakereporter{num}",
                password_hash=encrypted_password,
                session_info=None,
                verified=True,
            ) for num in iterator)
    elif acc_type == "victim99":
        db[C.USER_COLLECTION].insert_many(
            mongo.get_default_user_doc(
                email=f"victim{num}@demo.com",
                username=f"victim99_{num}",
                display_name=f"Victim99{num}",
                password_hash=encrypted_password,
                session_info=None,
                verified=True,
            ) for num in iterator)
    else:
        raise ValueError("Invalid account type")

def oauth_account_exist(db: Database):
    while True:
        email = input("Enter the email address: ")
        try:
            validate_email(email)
        except EmailNotValidError as e:
            print(str(e))
        
        username = email.split("@")[0]
        print(username, email)

        if does_user_exists(db, username.lower()):
            print("oauth account already exists")
            print("returning...")
            return None
        else:
            return email

def create_oauth_account(db: Database, acc_type: str, username: str, email: str):
    # strip email to username
    username = username.strip().replace(" ", "_")
    if acc_type == "user":
        db[C.USER_COLLECTION].insert_one(
            mongo.get_default_user_doc(
                email=email,
                username=username,
                display_name=username,
                password_hash=None,
                session_info=None,
                verified=True,
                oauth2=["google"],
            ),
        )
    elif acc_type == "mirai_plus":
        db[C.USER_COLLECTION].insert_one(
            mongo.get_default_user_doc(
                email=email,
                username=username,
                display_name=username,
                password_hash=None,
                session_info=None,
                verified=True,
                mirai_plus=True,
                oauth2=["google"],
            ),
        )
    elif acc_type == "admin":
        db[C.ADMIN_COLLECTION].insert_one(
            mongo.get_default_user_doc(
                email=email,
                username=username,
                is_admin=True,
                display_name=username,
                password_hash=None,
                session_info=None,
                verified=True,
                oauth2=["google"],
            ),
        )
    elif acc_type == "root":
        db[C.ADMIN_COLLECTION].insert_one(
            mongo.get_default_user_doc(
                email=email,
                username=username,
                is_admin=True,
                display_name=username,
                password_hash=None,
                session_info=None,
                verified=True,
                security={
                    "role": [C.ROOT],
                },
                oauth2=["google"],
            ),
        )
    else:
        raise ValueError("Invalid account type")


# --------------------------------------------------------
# - Checks if User exists & obtains the highest number
#---------------------------------------------------------
def does_user_exists(db: Database, username: str) -> int:
    user = db[C.USER_COLLECTION].find_one({
        "username":f"{username}"
    })
    
    if user is None: return 0

    return 1

NUMBER_REGEX = re.compile(r"^\d+$")
def get_n_to_generate(gentype) -> int:
    no_of_user = 0
    while True:
        print()

        if gentype == "user":
            no_of_user = input("Number of users to create: ")
        if gentype == "ban":
            no_of_user = input("Number of ban reports to create: ")
        if gentype == "report":
            no_of_user = input("Number of reports to create: ")

        if no_of_user.lower() == "x":
            return 0
        elif not re.fullmatch(NUMBER_REGEX, no_of_user):
            print("Please enter a number!", end="\n\n")
            continue
        else:
            return int(no_of_user)

# --------------------------------------------------------
# - Deletion functions
#---------------------------------------------------------
def delete_fake_users(db: Database, acc_type: str, user_count: int | None = 5) -> None:
    if acc_type == "user":
        db[C.USER_COLLECTION].delete_many({
            "username": {
                "$regex": r"^[uU]ser_\d+$"
            }
        })
    elif acc_type == "mirai_plus":
        db[C.USER_COLLECTION].delete_many({
            "username": {
                "$regex": r"^[mM]iraiplus_\d+$"
            }
        })
    elif acc_type == "admin":
        db[C.ADMIN_COLLECTION].delete_many({
            "username": {
                "$regex": r"^[aA]dmin_\d+$"
            }
        })
    elif acc_type == "root":
        db[C.ADMIN_COLLECTION].delete_many({
            "username": {
                "$regex": r"^[mM]aintenance_\d+$"
            }
        })
    elif acc_type == "all_normal":
        db[C.USER_COLLECTION].delete_many({
            "username": {
                "$regex": r"^([uU]ser|[fF]akereporter|[vV]ictim99)_\d+$"
            }
        })
    elif acc_type == "all_admin":
        db[C.ADMIN_COLLECTION].delete_many({
            "username": {
                "$regex": r"^([aA]dmin|[mM]aintenance|[sS]uper[rR]oot)_\d+$"
            }
        })
    elif acc_type == "fake_reporter":
        db[C.USER_COLLECTION].delete_many({
            "username": {
                "$regex": r"^[fF]akereporter_\d+$"
            }
        })
    elif acc_type == "victim99":
        db[C.USER_COLLECTION].delete_many({
            "username": {
                "$regex": r"^[vV]ictim99_\d+$"
            }
        })
    else:
        raise ValueError("Invalid account type")

def get_account_count(db: Database, acc_type: str) -> str:
    if acc_type == "user":
        user_count = db[C.USER_COLLECTION].count_documents({
            "security.role": {
                    "$elemMatch": {
                        "$eq": C.USER,
                        },
                
            },
        })

    elif acc_type == "admin":
        user_count = db[C.ADMIN_COLLECTION].count_documents({
            "security.role": {
                    "$elemMatch": {
                        "$eq": C.ADMIN,
                        },
                
            },
        })

    elif acc_type == "root":
        user_count = db[C.ADMIN_COLLECTION].count_documents({
            "security.role": {
                    "$elemMatch": {
                        "$eq": C.ROOT,
                        },
                
            },
        })

    elif acc_type == "all":
        user_count = db[C.USER_COLLECTION].count_documents({
            "security.role": {
                    "$elemMatch": {
                        "$eq": C.USER,
                        },
                
            },
        })
        
    elif acc_type == "fake_reporter":
        user_count = db[C.USER_COLLECTION].count_documents({
            "username": {
                "$regex": r"^[fF]akereporter_\d+$"
            }
        })
    elif acc_type == "victim99":
        user_count = db[C.USER_COLLECTION].count_documents({
            "username": {
                "$regex": r"^[vV]ictim99_\d+$"
            }
        })
    else:
        raise ValueError("Invalid account type")
    return user_count
# --------------------------------------------------------
# - Report Functions
#---------------------------------------------------------
def get_report_count(db: Database) -> str:
    report_count = db[C.REPORT_COLLECTION].count_documents(
        { "status": "open" }
    )
    if report_count == 0:
        return 0
    return report_count 

def create_fake_reports(db: Database, report_count: int | None = 5) -> None:
    largest_number = 1
    iterator = range(largest_number, largest_number + report_count)
    user_ids = tuple(bson.ObjectId() for _ in iterator)
    db[C.REPORT_COLLECTION].insert_many({
        "id": user_id,
        "title": f"Report {num}",
        "reasons": f"Report {num} description",
        "created_at": datetime.now(),
        "status": "open",
        "user_id": "user699F",
        "reported_by": "fakereporter",
    } for user_id, num in zip(user_ids, iterator))

def delete_fake_reports(db: Database, report_count: int | None = 5) -> None:
    db[C.REPORT_COLLECTION].delete_many({
        "title": {
            "$regex": r"^Report \d+$"
        }
    })

# retrieve all users in the databases
def get_all_users(db: Database) -> list[dict]:
    users = db[C.USER_COLLECTION].find({
        "security": {
                "role": [C.USER],
            },
    })

    return users

def create_demo_bans(db: Database, ban_count: int | None = 5) -> None:
    largest_number = 1
    iterator = range(largest_number, largest_number + ban_count)
    user_ids = tuple(bson.ObjectId() for _ in iterator)
    db[C.BAN_COLLECTION].insert_many({
        "id": user_id,
        "reason": f"Ban {num}",
        "created_at": datetime.now(),
        "banned_by": "fakereporter",
    } for user_id, num in zip(user_ids, iterator))
    #check for duplicates then add a higher number 
    #option when not x shouldnt end program,

def delete_demo_bans(db: Database, ban_count: int | None = 5) -> None:
    db[C.BAN_COLLECTION].delete_many({
        "reason": {
            "$regex": r"^Ban \d+$"
        }
    })


"""----------------------------------- END OF DEFINING FUNCTIONS -----------------------------------"""

def main():
    while True:
        debug_prompt = input("Debug mode? (Y/n): ").lower().strip()
        if debug_prompt not in ("y", "n", ""):
            print("Invalid input", end="\n\n")
            continue
        else:
            print()
            debug_flag = (debug_prompt != "n")
            break

    #get count of all accounts in db

    AVAILABLE_OPTIONS = ("1", "2","3","4","5","6","7","8","9","x","10","11")
    with (
        mongo.get_db_client(get_default=False, get_async=False, debug=debug_flag) as client,
        mongo.get_db_client(get_default=False, get_async=False, debug=debug_flag, get_admin_db=True) as admin
    ):
        while True:
            db = client[C.DB_NAME]
            admin_db = admin[C.ADMIN_DB_NAME]
            num_of_current_users = get_account_count(db, "user")
            num_of_current_admins = get_account_count(admin_db, "admin")
            num_of_current_maintenance = get_account_count(admin_db, "root")
            num_of_current_fake_reporters = get_account_count(db, "fake_reporter")
            num_of_current_victim99s = get_account_count(db, "victim99")
            num_of_current_reports = get_report_count(admin_db)

            list_of_users = get_all_users(db)
            for doc in list_of_users:
                username = doc["username"]
                print(username)

            find_users = db[C.USER_COLLECTION].find({
                "username": {
                    # TODO: Regex won't work here since the username is in the format "user_1"
                    "$regex": r"^(User|Admin|Maintenance|Super Root|Fakereporter|Victim99)_\d+$"
                }
            })

            choose_menu(
                user_count=num_of_current_users,
                admin_count=num_of_current_admins,
                maintenance_count=num_of_current_maintenance,
                report_count=num_of_current_reports,
                fake_reporter_count=num_of_current_fake_reporters,
                victim99_count=num_of_current_victim99s,
                debug=debug_flag
            )
            cmd_option = input("Enter option: ").lower().strip()
            if cmd_option not in AVAILABLE_OPTIONS:
                print("Invalid input", end="\n\n")
                continue
            elif cmd_option == "1":
                create_menu(
                    user_count=num_of_current_users,
                    admin_count=num_of_current_admins,
                    maintenance_count=num_of_current_maintenance,
                    report_count=num_of_current_reports,
                    fake_reporter_count=num_of_current_fake_reporters,
                    victim99_count=num_of_current_victim99s,
                    debug=debug_flag
                )
                cmd_option = input("Enter option: ").lower().strip()
                if cmd_option not in AVAILABLE_OPTIONS:
                    print("Invalid input", end="\n\n")
                    continue
                elif cmd_option == "1":
                    #check if users already exist
                    if num_of_current_users > 0:
                        print(f"{num_of_current_users} Users already exist", end="\n\n")
                        user_option=input("Would you like to create more users? (Y/n): ")
                        if user_option not in ("y", "n", ""):
                            print("Invalid input", end="\n\n")
                            continue
                        elif user_option == "n":
                            print("returning...")
                            continue
                        elif user_option == "y":
                            pass
                        else:
                            print("Invalid input", end="\n\n")
                            print("returning...")
                            continue
                    # 1. Create X number of test users
                    # make it such that if users exists it iterates over the new users so it will have to add upon the existing users
                    no_of_users = get_n_to_generate("user")
                    if no_of_users == 0:
                        continue
                    create_fake_users(db, C.USER, no_of_users)
                    print(f"Created {no_of_users} fake users", end="\n\n")
                    print("returning...")

                elif cmd_option == "2":
                    no_of_users = get_n_to_generate("user")
                    if no_of_users == 0:
                        continue
                    create_fake_users(db,C.MIRAI_PLUS, no_of_users)
                    print('work in progress')
                    print("returning...")
                    pass
                
                elif cmd_option == "3":
                    
                    delete_fake_users(db, "fake_reporter", 2)
                    delete_fake_users(db, "victim99", 2)
                    delete_fake_reports(admin_db, 5)

                    create_fake_users(db, "fake_reporter", 1)
                    create_fake_users(db, "victim99", 1)
                    create_fake_reports(admin_db, 5)

                    print(f"Created fake reports", end="\n\n")
                    print("returning...")
                elif cmd_option == "4":
                    #make bans
                    no_of_demo_bans = get_n_to_generate("ban")
                    if no_of_demo_bans == 0:
                        continue
                    create_demo_bans(admin_db,no_of_demo_bans)
                    print(f"Created {no_of_demo_bans} fake demo bans", end="\n\n")
                    print("returning...")
                
                else:
                    print("returning...")
                    continue
            elif cmd_option == "2":
                delete_menu(
                    user_count=num_of_current_users,
                    admin_count=num_of_current_admins,
                    maintenance_count=num_of_current_maintenance,
                    report_count=num_of_current_reports,
                    fake_reporter_count=num_of_current_fake_reporters,
                    victim99_count=num_of_current_victim99s,
                    debug=debug_flag
                )
                cmd_option = input("Enter option: ").lower().strip()
                if cmd_option not in AVAILABLE_OPTIONS:
                    print("Invalid input", end="\n\n")
                    continue
                elif cmd_option == "1":
                    # 1. Delete X number of test users
                    no_of_users = get_n_to_generate("user")
                    if no_of_users == 0:
                        continue
                    delete_fake_users(db, C.USER, no_of_users)
                    print(f"Deleted {no_of_users} fake users", end="\n\n")
                    print("returning...")
                elif cmd_option == "2":
                    no_of_users = get_n_to_generate("user")
                    if no_of_users == 0:
                        continue
                    delete_fake_users(db, C.MIRAI_PLUS, no_of_users)
                    print('work in progress')
                    print("returning...")
                    pass
                elif cmd_option == "3":
                    no_of_admins = get_n_to_generate("user")
                    if no_of_admins == 0:
                        continue
                    delete_fake_users(admin_db, C.ADMIN, no_of_admins)
                    print(f"Deleted {no_of_admins} fake admins", end="\n\n")
                    print("returning...")
                elif cmd_option == "4":
                    no_of_maintenance = get_n_to_generate("user")
                    if no_of_maintenance == 0:
                        continue
                    delete_fake_users(admin_db, C.ROOT, no_of_maintenance)
                    print(f"Deleted {no_of_maintenance} fake maintenance", end="\n\n")
                    print("returning...")
                elif cmd_option == "5":
                    no_of_reports = get_n_to_generate("user")
                    if no_of_reports == 0:
                        continue
                    delete_fake_reports(admin_db, no_of_reports)
                    print(f"Deleted {no_of_reports} fake reports", end="\n\n")
                    print("returning...")
                elif cmd_option == "6":
                    # delete all accounts
                    delete_fake_users(db, "all_normal")
                    delete_fake_users(admin_db, "all_normal")
                    print(f"Delete all accounts")
                    print("returning...")
                else:
                    print("returning...")
                    continue
            elif cmd_option == "3":
                oauth_menu()
                cmd_option = input("Enter option: ").lower().strip()
                if cmd_option == "1":
                    account_exist = oauth_account_exist(db)
                    print(account_exist)
                    if account_exist == None:
                        continue
                    email = account_exist
                    username = email.strip().split("@")[0]
                    create_oauth_account(db,"user",username,email)
                    print("oauth account created")
                    print("returning...")
                    continue
                elif cmd_option == "2":
                    account_exist = oauth_account_exist(db)
                    if account_exist == None:
                        continue
                    email = account_exist
                    username = email.strip().split("@")[0]
                    create_oauth_account(db,"miraiplus",username,email)
                    print("oauth account created")
                    print("returning...")
                    continue
                elif cmd_option == "3":
                    account_exist = oauth_account_exist(db)
                    if account_exist == None:
                        continue
                    email = account_exist
                    username = email.strip().split("@")[0]
                    create_oauth_account(admin_db,"admin",username,email)
                    print("oauth account created")
                    print("returning...")
                    continue
                elif cmd_option == "4":
                    account_exist = oauth_account_exist(db)
                    if account_exist == None:
                        continue
                    email = account_exist
                    username = email.strip().split("@")[0]
                    create_oauth_account(admin_db,"root",username,email)
                    print("oauth account created")
                    print("returning...")
                    continue
                
                else:
                    print("returning...")
                    continue
            else:
                break
        print()
        print("Shutting down...")
        input("Please press ENTER to exit...")
        return

if __name__ == "__main__":
    main()