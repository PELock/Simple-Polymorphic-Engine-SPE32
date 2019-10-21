
;██████████████████████████████████████████████████████████████████████████████████████████████
;
; SIMPLE POLYMORPHIC ENGINE v1.0
;
; The SPE32 engine is an amateur project that can be used to demonstrate what
; polymorphic engines are. I wrote it some time ago, but I thought
; it would be a good idea to make it public.
;
; Bartosz Wójcik | https://www.pelock.com
;
;██████████████████████████████████████████████████████████████████████████████████████████████

.686					; Pentium 4 instructions
.mmx					; +MMX
.xmm					; +SSE, +SSE2
.model flat,stdcall

;██████████████████████████████████████████████████████████████████████████████████████████████
;
; libraries
;
;██████████████████████████████████████████████████████████████████████████████████████████████

includelib	c:\masm32\lib\kernel32.lib
includelib	c:\masm32\lib\user32.lib
includelib	c:\masm32\lib\gdi32.lib

;██████████████████████████████████████████████████████████████████████████████████████████████
;
; headers
;
;██████████████████████████████████████████████████████████████████████████████████████████████

include		c:\masm32\include\kernel32.inc
include		c:\masm32\include\user32.inc
include		c:\masm32\include\gdi32.inc

include		c:\masm32\include\windows.inc

POLY_DECRYPTOR_BUFFER_SIZE	equ 255

.data
	szCpt		db 'SPE32 - visit https://www.pelock.com',0
	szTest		db 'SIMPLE POLYMORPHIC ENGINE v1.0 - Bartosz Wojcik',0
.code

;██████████████████████████████████████████████████████████████████████████████████████████████
;
; SPE32 engine code (.code section must be writeable)
;
;██████████████████████████████████████████████████████████████████████████████████████████████

	include		spe32.asm

;██████████████████████████████████████████████████████████████████████████████████████████████
;
; applicatin entrypoint main()
;
;██████████████████████████████████████████████████████████████████████████████████████████████

_start:

;──────────────────────────────────────────────────────────────────────────────────────────────
; calculate delta offset
;──────────────────────────────────────────────────────────────────────────────────────────────
	call	_delta
_delta:	pop	ebp
	sub	ebp,offset _delta

;──────────────────────────────────────────────────────────────────────────────────────────────
; random generator within SPE32 seed
;──────────────────────────────────────────────────────────────────────────────────────────────
	call	GetTickCount
	lea	eax,[eax*8+eax]
	lea	ebx,[eax*8+edx]			; store random seed in EBX

;──────────────────────────────────────────────────────────────────────────────────────────────
; allocate executable memory for temporary encryptor code
;──────────────────────────────────────────────────────────────────────────────────────────────
	push	PAGE_EXECUTE_READWRITE
	push	MEM_RESERVE or MEM_COMMIT
	push	POLY_DECRYPTOR_BUFFER_SIZE
	push	0
	call	VirtualAlloc
	mov	edi,eax

;──────────────────────────────────────────────────────────────────────────────────────────────
; encrypt sample_code_to_encrypt() function code and generate polymorphic
; decryption code
;──────────────────────────────────────────────────────────────────────────────────────────────
	push	eax				; save allocated memory pointer

	push	ebx				; random seed
	push	PRESERVE_REGS or PRESERVE_FLAGS	; flags
	push	edi				; buffer to store encryptor body (temp buffer)
	push	POLY_DECRYPTOR_BUFFER_SIZE	; size of buffer to store encryptor body
	push	offset output_poly_decryptor	; pointer to buffer that will recieve poly decryptor body
	push	offset sample_code_to_encrypt	; pointer to buffer that will be encrypted
	push	sample_code_to_encrypt_len/4	; size of code or data to encrypt (in DWORDs units)
	call	SPE32				; encrypt code/data and generate
						; polymorphic decryptor

;──────────────────────────────────────────────────────────────────────────────────────────────
; execute polymorphic decryptor code
;──────────────────────────────────────────────────────────────────────────────────────────────

; for debugging purposes
int 3

; jump to the decryption code
	jmp	output_poly_decryptor

exit:

;──────────────────────────────────────────────────────────────────────────────────────────────
; release the memory
;──────────────────────────────────────────────────────────────────────────────────────────────
	pop	eax				; restore allocated memory pointer

	push	MEM_RELEASE
	push	0
	push	eax
	call	VirtualFree

	push	0
	call	ExitProcess

;──────────────────────────────────────────────────────────────────────────────────────────────
; this buffer will receive the decryptor body
;──────────────────────────────────────────────────────────────────────────────────────────────
output_poly_decryptor:

	db	1000h dup(0)

;██████████████████████████████████████████████████████████████████████████████████████████████
;
; this code is going to be encrypted
;
;██████████████████████████████████████████████████████████████████████████████████████████████

align 16
sample_code_to_encrypt:

	push	MB_ICONINFORMATION
	push	offset szTest
	push	offset szCpt
	push	0
	call	MessageBoxA

	jmp	exit

	dd	10 dup(90h)			; safe space alignment

sample_code_to_encrypt_len equ $-sample_code_to_encrypt

end _start
