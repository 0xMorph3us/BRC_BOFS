# Compiler definitions
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
OPTIONS := -masm=intel -O0 

# Paths
OUTPUT_DIR := .

# Macro for building and copying
define build
	$(CC_x64) $(OPTIONS) $(strip $(2)) -c $(1).c -o $(OUTPUT_DIR)/$(3).x64.o -m64 -s
	$(CC_x86) $(OPTIONS) $(strip $(2)) $(strip $(4)) -c $(1).c -o $(OUTPUT_DIR)/$(3).x86.o -m32 -s
	strip --strip-unneeded $(OUTPUT_DIR)/$(3).x64.o
	strip --strip-unneeded $(OUTPUT_DIR)/$(3).x86.o
endef

.PHONY: all smbtakeover getnetlocalgroup getnetloggedon getnetsession getregsession

all: smbtakeover getnetlocalgroup getnetloggedon getnetsession  getregsession 

smbtakeover:
	$(call build,smbtakeover/main,,smbtakeover)

getnetlocalgroup:
	$(call build,getnetlocalgroup/main,,getnetlocalgroup)

getnetloggedon:
	$(call build,getnetloggedon/main,,getnetloggedon)

getnetsession:
	$(call build,getnetsession/main,,getnetsession)

getregsession:
	$(call build,getregsession/main,,getregsession)

clean:
	rm -f $(OUTPUT_DIR)/*.x64.o $(OUTPUT_DIR)/*.x86.o