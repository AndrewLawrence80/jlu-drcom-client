CC = gcc
CFLAGS = -Iinclude -Wall
LDFLAGS = -lpthread

TARGET = build/bin/drclient_jlu

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:src/%.c=build/obj/%.o)
DEPS = $(OBJS:build/obj/%.o=build/dep/%.d)

all: $(TARGET)

# object: dependence
# $@: left side of `:`
# $<: first parameter
build/obj/%.o: src/%.c | build/obj build/dep
	$(CC) $(CFLAGS) -MMD -MF $(patsubst build/obj/%.o,build/dep/%.d,$@) -c $< -o $@

# $^: right side of `:`
$(TARGET): $(OBJS) | build/bin
	$(CC) -o $@ $^ $(LDFLAGS)

build/obj build/dep build/bin:
	mkdir -p $@

-include $(DEPS)

.PHONY: clean

clean:
	rm -rf build