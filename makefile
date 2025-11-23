

myLDAP	:	myLDAP.c
	gcc -Wall -Wextra -O2 -I/usr/include/mysql myLDAP.c -lmysqlclient -lpthread -lcrypt -o myLDAP
