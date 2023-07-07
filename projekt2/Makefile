PROJ=kry
PERSONAL_NUMBER=250288

CC=gcc
CFLAGS=-Wall -Wextra -O2 -MMD -g
LDFLAGS = -lssl -lcrypto

ZIP_FILE=$(PERSONAL_NUMBER).zip

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
DEPS=$(patsubst %.c,%.d,$(SRCS))

$(PROJ): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROJ) $^

build: $(PROJ)

run: $(PROJ)
	./$(PROJ) $(TYPE) $(PORT)

doc: documentation.typ
	typst c $^

pack: 
	zip $(ZIP_FILE) *.c *.h Makefile documentation.*

-include $(DEPS)

.PHONY: clean
clean:
	rm $(PROJ) $(OBJS) $(DEPS)
