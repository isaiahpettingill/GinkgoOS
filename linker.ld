/*
 * Based on Limine's 0BSD-licensed x86-64 template linker script.
 * The kernel is linked into the top 2 GiB, as required by the Limine protocol.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    limine_requests PT_LOAD;
    text            PT_LOAD FLAGS(5); /* read + execute */
    rodata          PT_LOAD FLAGS(4); /* read */
    data            PT_LOAD FLAGS(6); /* read + write */
}

SECTIONS
{
    . = 0xffffffff80000000;

    .limine_requests :
    {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :limine_requests

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .text :
    {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .rodata :
    {
        *(.rodata .rodata.*)
    } :rodata

    .note.gnu.build-id :
    {
        *(.note.gnu.build-id)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .data :
    {
        *(.data .data.*)
    } :data

    .bss :
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
