
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


Flag File: /passoire/web/flag_3
Content: flag_3 is b2206f0b21de1ed5ecd4dbf0539d66ec6f756b1b
Description: If you read this you should wonder wether this flag can be seen by guessing its url. If you think this is possible, remove this file.


SECTION 2: FLAGS HIDDEN IN OTHER FILES
-----------------------------------------

Location: /passoire/web/index.php (line containing flag_13)
Content: flag_13 is 48a8c2049835c355cdaa42f0386d22c76ff04db9
Description: This flag is not visible in the html of this page. If an attacker can read this, this is a bad sign. (Found in commented PHP code)


Location: /passoire/config/passoire.sql (database dump)
Content: flag_5 is 24b3a52ee00e5da545a95071c1a21419f9afa417
Description: Found in database dump file. Username: flag_5, Email: see-password-hash@that-is-the-fl.ag, Password hash: 24b3a52ee00e5da545a95071c1a21419f9afa417



