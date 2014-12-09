# ===================================================================
# These are the usual GCC CFLAGS to set in all projects,but with a 
# few others that may be needed to build libraries.
# You may need to adjust these for different platforms.
# OPTFLAGS variable lets people augment the build options as needed.
# ===================================================================
CFLAGS=-g -O2 -Wall -Wextra -Isrc -rdynamic -DNDEBUG $(OPTFLAGS)

# ===================================================================
# Options used when linking a library, and allows someone else to 
# augment the linking options using the OPTLIBS variable.
# ===================================================================
LIBS=-ldl $(OPTLIBS)

# ===================================================================
# Setting an optional variable called PREFIX that will only have 
# this value if the person running the Makefile didn't already 
# give a PREFIX setting. That's what the ?= does.
# ===================================================================
PREFIX?=/usr/local

# ===================================================================
# This fancy line of awesome dynamically creates the SOURCES variable 
# by doing a wildcard search for all *.c files in the src/ directory. 
# You have to give both src/**/*.c and src/*.c so that GNU make will 
# include the files in src and also the ones below it.
# ===================================================================
SOURCES=$(wildcard src/**/*.c src/*.c)

# ===================================================================
# use the patsubst to take the SOURCES list of *.c files and 
# make a new list of all the object files. You do this by 
# telling patsubst to change all %.c extensions to %.o 
# and then those are assigned to OBJECTS.
# ===================================================================
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

# ===================================================================
# Using the wildcard again to find all the test source files for 
# the unit tests. These are separate from the library's source files.
# ===================================================================
TEST_SRC=$(wildcard tests/*_tests.c)
# ========================================================================
# Using the same patsubst trick to dynamically get all the TEST targets. 
# stripping away the .c extension so that a full program will be made 
# with the same name. Previously I had replaced the .c with {.o} 
# so an object file is created.
# ========================================================================
TESTS=$(patsubst %.c,%,$(TEST_SRC))

# ===================================================================
# Finally, we say the ultimate target is build/libYOUR_LIBRARY.a, 
# change it to be whatever library you are actually trying to build.
# ===================================================================
TARGET=build/libYOUR_LIBRARY.a
SO_TARGET=$(patsubst %.a,%.so,$(TARGET))

# =====================================
# augment Demonstration..
# When you run make you can do this:
# this installs the library into /tmp
# $ make PREFIX=/tmp install
# this tells it to add pthreads
# $ make OPTFLAGS=-pthread
# =====================================

# =============================================================================
# the first target is what make will run by default when no target is given. 
# In this case it's called all: and it gives $(TARGET) tests as the targets 
# to build. Look up at the TARGET variable and you see that's the library, 
# so all: will first build the library. The tests target is then further 
# down in the Makefile and builds the unit tests.
# The Target Build :
# =============================================================================
all: $(TARGET) $(SO_TARGET) tests

# =============================================================================
# Another target for making "developer builds" that introduces a technique 
# for changing options for just one target. 
# If I do a "dev build" I want the CFLAGS to include options like -Wextra 
# that are useful for finding bugs. If you place them on the target line as 
# options like this, then give another line that says the original target 
# (in this case all) then it will change the options you set. 
# I use this for setting different flags on different platforms that need it.
# =============================================================================
dev: CFLAGS=-g -Wall -Isrc -Wall -Wextra $(OPTFLAGS)
dev: all

# =============================================================================
# Builds the TARGET library, whatever that is, 
# and also uses the same trick from line all:
# of giving a target with just options changes to alter them for this run. 
# In this case I'm adding -fPIC just for the library build using 
# the += syntax to add it on.
# =============================================================================
$(TARGET): CFLAGS += -fPIC
# =============================================================================
# Now the real target where I say first make the build directory, 
# then compile all the OBJECTS.
# =============================================================================
$(TARGET): build $(OBJECTS)
# =============================================================================
# Runs the ar command which actually makes the TARGET. 
# The syntax $@ $(OBJECTS) is a way of saying, 
# "put the target for this Makefile source here and all the OBJECTS after that". 
# In this case the $@ maps back to the $(TARGET) on line $(TARGET): CFLAGS += -fPIC, 
# which maps to build/libYOUR_LIBRARY.a.
# =============================================================================
	ar rcs $@ $(OBJECTS)
# =============================================================================
# Finally, to make the library you run ranlib on the TARGET and it's built.
# =============================================================================
	ranlib $@

$(SO_TARGET): $(TARGET) $(OBJECTS)
	$(CC) -shared -o $@ $(OBJECTS)
# =============================================================================
# This just makes the build/ or bin/ directories if they don't exist.
# This is then referenced from line $(TARGET): CFLAGS += -fPIC,
# when it gives the build target to make sure the build/ directory is made.
# =============================================================================

build:
	@mkdir -p build
	@mkdir -p bin

# ============================================================================================
# The Unit Tests:
# If you have a target that's not "real", but there is a directory or file with that name, 
# then you need to tag the target with .PHONY: so make will ignore the file and always run.
# ============================================================================================
.PHONY: tests
# ============================================================================================
# Use the same trick for modifying the CFLAGS variable to add the TARGET to the build 
# so that each of the test programs will be linked with the TARGET library.
# ============================================================================================
tests: CFLAGS += $(TARGET)
# ============================================================================================
# the actual tests: target which depends on all the programs listed in the TESTS variable 
# we created in the header. This one line actually says, "Make, use what you know about 
# building programs and the current CFLAGS settings to build each program in TESTS."
# ============================================================================================
tests: $(TESTS)
# Call for shell script
	sh ./tests/runtests.sh
# ===========================================================================================================
# This puts the valgrind logs into /tmp/valgrind-*.log so you can go look and see what might be going on.
# ===========================================================================================================
valgrind:
	VALGRIND="valgrind --log-file=/tmp/valgrind-%p.log" $(MAKE)

# ==================================================================================
# The Cleaner:
# This cleans out most of the junk that various compilers and tools leave behind. 
# It also gets rid of the build/ directory and uses a trick at the end to cleanly 
# erase the weird files leaves behind for debugging purposes.
# ==================================================================================
clean:
	rm -rf build $(OBJECTS) $(TESTS)
	rm -f tests/tests.log
	find . -name "*.gc*" -exec rm {} \;
	rm -rf `find . -name "*.dSYM" -print`

# ==================================================================================
# The Install
# This makes install: depend on the all: target so that when you run make install 
# it will be sure to build everything.
# ==================================================================================
install: all
# ===========================================================================================================
# make the install as flexible as possible by using two variables that are conventions for installers. 
# DESTDIR is handed to make by installers that do their builds in secure or odd locations to build packages. 
# PREFIX is used when people want the project to be installed in someplace other than /usr/local
# ===========================================================================================================
	install -d $(DESTDIR)/$(PREFIX)/lib/
	install $(TARGET) $(DESTDIR)/$(PREFIX)/lib/

# =========================================================
# The Checker:
# dig out any attempts to use the "bad" functions in C.
# =========================================================
BADFUNCS='[^_.>a-zA-Z0-9](str(n?cpy|n?cat|xfrm|n?dup|str|pbrk|tok|_)|stpn?cpy|a?sn?printf|byte_)'
check:
	@echo Files with potentially dangerous functions.
	@egrep $(BADFUNCS) $(SOURCES) || true
