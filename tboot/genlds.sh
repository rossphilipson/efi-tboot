#! /bin/sh

RO_DATA_SECTION=".rdata"

if [ "$1" == "gcc" ]; then
    RO_DATA_SECTION=".rodata"
fi

cat << EOF >> tboot.lds
SECTIONS
{
  .text : {
    . = ALIGN(4096);
    *(.text)
    *($RO_DATA_SECTION)
    *(SORT($RO_DATA_SECTION*))
  }
}
EOF
