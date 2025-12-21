
SECTION 1: FLAGS IN DEDICATED FLAG FILES
-----------------------------------------

Flag File: /home/admin/flag_14
Content: flag_14 is 1a351c7c9661df68a635c440dd5f6b6a31af513d
Description: Keep this flag if you want to keep user admin, otherwise you can remove it.

Flag File: /home/passoire/flag_1
Content: flag_1 is ac40788aab08c12a7cb5d52ca4d712f49fe24a21
Description: Congratulation you found the first flag. This means that you are all set to start the project. You should submit this flag on NextILearn before Deadline 1. (Do not remove this file.)

Flag File: /root/flag_2
Content: flag_2 is 4879de812813ea4b9e557b03fa7150283eaf60ca
Description: Since this flag is the home directory of user root, owned by root and has permissions -r--------, only a user with root privileges should be able access it. Depending on how you modified this container, this may be harder to get for an opponent.

Flag File: /passoire/crypto-helper/flag_9
Content: flag_9 is d9ab38bccb67467845a43271d1d9d4b24c83d862
Description: This flag is readable by an attacker if something is insecure in the crypto-helper api. But that should not be the case, right?

Flag File: /passoire/web/uploads/flag_6
Content: flag_6 is 23a2011900e8a1cc8d3c8247cf2f0c8e763e6da8
Description: This is an old file, that is not tracked in the file database. No one should be able to acces it right?

Flag File: /passoire/web/flag_3
Content: flag_3 is b2206f0b21de1ed5ecd4dbf0539d66ec6f756b1b
Description: If you read this you should wonder wether this flag can be seen by guessing its url. If you think this is possible, remove this file.


SECTION 2: FLAGS HIDDEN IN OTHER FILES
-----------------------------------------

Location: /passoire/crypto-helper/server.js (line containing flag_10)
Content: flag_10 is 1a1fd2ed43d096dd09bb3c7301e0b23069337fe6
Description: Found in API endpoint /flag. This flag is exposed through an insecure API endpoint that returns the flag directly.

Location: /passoire/web/index.php (line containing flag_13)
Content: flag_13 is 48a8c2049835c355cdaa42f0386d22c76ff04db9
Description: This flag is not visible in the html of this page. If an attacker can read this, this is a bad sign. (Found in commented PHP code)

Location: /passoire/web/index.php (line containing flag_4)
Content: flag_4 is 164bf3a11d8ce5f94a3af4553130fa6e66df2e45
Description: Sometimes developpers forget important information in the source code of web pages. You can remove this flag. You can find an example of such a thing having happened here https://missouriindependent.com/2022/02/23/claim-that-reporter-hacked-state-website-was-debunked-parson-still-says-hes-a-criminal/

Location: /passoire/web/uploads/secret
Content: flag_7 is 3cee170ea5635fc3aae1a885fb0530ab5694b1c1
Description: No one without the link should be able to access this file.

Location: /passoire/config/passoire.sql (database dump)
Content: flag_5 is 24b3a52ee00e5da545a95071c1a21419f9afa417
Description: Found in database dump file. Username: flag_5, Email: see-password-hash@that-is-the-fl.ag, Password hash: 24b3a52ee00e5da545a95071c1a21419f9afa417


SECTION 3: FLAGS IN DATABASE
-----------------------------------------

Database: passoire
Source: config/passoire.sql (database dump file)
Table: users
Column: password hash field
Flag: flag_5 is 24b3a52ee00e5da545a95071c1a21419f9afa417
Description: This flag is stored as a password hash in the users table. The username is flag_5 and the email is see-password-hash@that-is-the-fl.ag


SECTION 4: ENVIRONMENT VARIABLES
-----------------------------------------

No flags found in environment variables.


SECTION 5: SEARCH SUMMARY
-----------------------------------------
Total flags found: 11
Flags in dedicated files: 6
Flags hidden in other files: 5
Flags in database: 1
Flags in environment: 0
