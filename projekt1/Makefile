PROJ=kry
PERSONAL_NUMBER=250288
ZIPFILE=$(PERSONAL_NUMBER).zip

CC=gcc
CFLAGS=-Wall -Wextra -Werror -Wpedantic -O2

$(PROJ): kry.c

doc: documentation.typ
	typst c $<

pack: kry.c Makefile documentation*
	zip $(ZIPFILE) $^

.PHONY: clean
clean:
	rm *.o $(PROJ)
