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


smbtakeover:
	$(call build,main,,smbtakeover)