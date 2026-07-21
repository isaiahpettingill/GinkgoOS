ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R W */
}

SECTIONS
{
    . = 0x00400000;

    .text :
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    . = ALIGN(0x1000);
    .rodata :
    {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.eh_frame .eh_frame_hdr)
    } :rodata

    . = ALIGN(0x1000);
    .data :
    {
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .bss (NOLOAD) :
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
    }
}
