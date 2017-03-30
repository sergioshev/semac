NORMAL_TARGETS = semac.php
LIB_DEST = /usr/local/lib/semac


install: 
	install -m 755 -d $(LIB_DEST)
	install -m 644 $(NORMAL_TARGETS) $(LIB_DEST)

uninstall:
	rm -r $(LIB_DEST)
