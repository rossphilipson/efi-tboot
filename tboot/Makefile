# Build with GCC compiler, note .rodata section in .lds file
#CC = gcc
# Build with MinGW compiler, note .rdata section in .lds file
CC = x86_64-w64-mingw32-gcc
LD = x86_64-w64-mingw32-ld
CFLAGS = -ffreestanding -fPIE -fno-exceptions -fshort-wchar -mno-ms-bitfields # Too much: -DTPM_TRACE
CFLAGS += -I/usr/include/efi -I/usr/include/efi/x86_64 -I/usr/include/efi/protocol -Iinclude
AFLAGS = -D__ASSEMBLY__ $(patsubst -std=gnu%,,$(CFLAGS))
#LDFLAGS = -nostdlib -Wl,-pie -shared -Wl,--no-seh -Wl,--subsystem,10 -e efi_main
LDFLAGS = -nostdlib -pie -shared --no-seh --subsystem=10 -e efi_main
ASM = launch.S bits.S # must be in order
SRC = $(wildcard *.c)
OBJ = $(ASM:.S=.o) # must be first
OBJ += $(SRC:.c=.o)

# Banner
CFLAGS += -DTBOOT_CHANGESET=\""$(shell ((hg parents --template "{isodate|isodate} {rev}:{node|short}" >/dev/null && hg parents --template "{isodate|isodate} {rev}:{node|short}") || echo "2016-05-18 12:00 -0800 1.9.4") 2>/dev/null)"\"


.PHONY: all
all: tboot.lds tboot.efi tboot.dsm

tboot.efi: $(OBJ)
	$(LD) tboot.lds $(LDFLAGS) $^ -o $@

# With lds
#tboot.efi: $(OBJ)
#	$(CC) -T lds/tboot2.lds $(LDFLAGS) $^ -o $@
#	$(CC) -Wl,lds/tboot2.lds $(LDFLAGS) $^ -o $@

# Grrr someone is frobbing the stack
tpm_20.o: tpm_20.c
	$(CC) $(CFLAGS) -mno-stack-arg-probe -o $@ -c $<

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.S
	$(CC) $(AFLAGS) -c $< -o $@

tboot.lds:
	$(PWD)/genlds.sh $(CC)

tboot.dsm:
	mingw-objdump -d tboot.efi > tboot.dsm

.PHONY: clean
clean:
	rm -f tboot.efi *.o tboot.dsm tboot.lds
