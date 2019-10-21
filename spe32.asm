
;██████████████████████████████████████████████████████████████████████████████████████████████
;
; SIMPLE POLYMORPHIC ENGINE v1.0
;
; Features:
;
; - entire code is position independent (delta offset is used to access data)
; - XOR, ADD, SUB used for encryption
; - junk opcodes generation - add,adc,sub,sbb,rol,ror,rcr,rcl,shl,shr,not,neg,dec,inc
;
; API:
;
; push    dwRandomSeed
; push    iFlags
; push    lpEncryptor
; push    lEncryptor
; push    lpDestination
; push    lpSource
; push    cSize
; call    SPME32
;
; Parameters:
;
; dwRandomSeed  - random seed
; iFlags        - see below
; lpEncryptor   - buffer to store encryptor body
; lEncryptor    - size of buffer to store encryptor body
; lpDestination - pointer to buffer that will recieve poly decryptor body
;                 it must be large enough
; lpSource      - pointer to buffer that will be encrypted, and after decryption
;                 poly decryptor jumps there (+delta offset)
; cSize         - size of code or data to encrypt (in DWORDs units)
;
; Returned value:
;
; eax           - size of poly decryptor
;
; Bartosz Wójcik | https://www.pelock.com
;
;██████████████████████████████████████████████████████████████████████████████████████████████

PRESERVE_REGS	equ 00000000000000000000000000000001b
PRESERVE_FLAGS	equ 00000000000000000000000000000010b
DEBUG_MODE	equ 00000000000000000000000000000100b

GEN_JUNKS	equ ON				; junk generator ON/OFF
JUNKS		equ 2				; junks per call to _gen_junks proc
REG_STATE	equ 1				; save and restore after decryption reg state

; x86 registers IDs
_EAX		equ 0
_ECX		equ 1
_EDX		equ 2
_EBX		equ 3
_ESP		equ 4
_EBP		equ 5
_ESI		equ 6
_EDI		equ 7

; helper macro to put int3 in the output code
@bpx	macro
	mov	al,0CCh
	stosb
endm

SPE32 proc near

	pop	eax				; return address

	pop	ecx				; code size (in DWORD units)
	pop	esi				; source
	pop	edi				; destination of poly decryptor
	pop	edx				; buffer size
	pop	ebx				; encryptor buffer
	pop	dword ptr[ebp+_spe32_flags]	; extra flags
	pop	dword ptr[ebp+_spe32_seed]	; random seed

	push	eax				; save return address

	push	edi				; save stdcall registers
	push	ebx
	push	esi

	mov	dword ptr[ebp+_spe32_encryptor],ebx

fill_nops:
	mov	byte ptr[ebx+edx-1],90h		;\
	dec	edx				; > fill encryptor buffer with NOPs
	jne	fill_nops			;/

choose_rnd_regs:

	pushad

get_random_for_reg:
	mov	al,7
	call	brandom32
	xchg	eax,ecx
	jecxz	get_random_for_reg

	lea	edx, [ebp+used_registers]	; point to registers
mangle_regs:
	push	edx

	mov	eax,dword ptr[edx]
	xchg	al,ah
	rol	eax,8
	xchg	al,ah

	mov	dword ptr[edx],eax
	inc	edx

	mov	eax,dword ptr[edx]
	rol	eax,16
	xchg	al,ah
	mov	dword ptr[edx],eax
	inc	edx

	mov	eax,dword ptr[edx]
	ror	eax,16
	xchg	al,ah
	mov	dword ptr[edx],eax
	
	pop	edx

	loop	mangle_regs

	popad

	call	_debug_mode

IFDEF REG_STATE
	mov	edx,dword ptr[ebp+_spe32_flags]
	test	edx,PRESERVE_REGS
	je	__check_flags

	mov	al,60h				; pushad
	stosb

__check_flags:

	test	edx,PRESERVE_FLAGS
	je	__skip_save_all

	mov	al,9Ch				; pushfd
	stosb

__skip_save_all:
ENDIF
	call	_gen_junks

	mov	al,0B8h				; mov preg,offset source
	or	al,byte ptr[ebp+preg]		;
	stosb					;

	mov	byte ptr[ebx],al
	inc	ebx
	mov	dword ptr[ebx],esi
	add	ebx,4

	mov	eax,esi				; source offset

	neg	eax				; neg
	stosd

	mov	ax,0D8F7h			; neg preg
	or	ah,byte ptr[ebp+preg]
	stosw 
	call	_gen_junks

	mov	al,03h				; add preg,ebp
	stosb					; lame way ;)
	mov	al,byte ptr[ebp+preg]
	shl	al,3
	or	al,_EBP
	or	al,11000000b
	stosb

	call	_gen_junks

	mov	al,0B8h				; mov creg,size_fo_code
	or	al,byte ptr[ebp+creg]
	stosb

	mov	byte ptr[ebx],al
	inc	ebx

	mov	dword ptr[ebx],ecx
	add	ebx,4

	mov	eax,ecx				; ecx size
	stosd

	mov	dword ptr[ebp+__loop_here],edi

						; 8Bh 000b 00 000
						;     ^vreg   ^preg
	mov	ax,008Bh			; mov vreg,[preg]
	or	ah,byte ptr[ebp+vreg]
	shl	ah,3
	or	ah,byte ptr[ebp+preg]
	stosw

	mov	word ptr[ebx],ax
	add	ebx,2+100-3-5-1-1-10-3
	push	ebx

	push	ecx

_get_passes:
	mov	al,7
	call	brandom32
	xchg	eax,ecx
	jecxz	_get_passes

__gen_:
	push	ecx

	call	_gen_junks

;██████ MAKE XOR,ADD,SUB ███████████████████████████████████████████████████████████████████████
	mov	al,81h
	stosb

	mov	byte ptr[ebx-2],al

	mov	al,(_crypt_opcodes_len)/2
	call	brandom32

	mov	ax,word ptr[ebp+eax*2+_crypt_opcodes]
	or	al,byte ptr[ebp+vreg]
	mov	byte ptr[ebx-1],al
	shr	eax,8
	or	al,byte ptr[ebp+vreg]
	stosb

	call	random32
	stosd

	mov	dword ptr[ebx],eax
	sub	ebx,6

	call	_gen_junks

	pop	ecx
	loop	__gen_

	
	pop	ecx

	pop	ebx
	add	ebx,4

	mov	al,89h				; mov [preg],vreg
	stosb

	mov	byte ptr[ebx],al
	inc	ebx

	mov	al,byte ptr[ebp+vreg]
	shl	al,3
	or	al,byte ptr[ebp+preg]
	stosb

	mov	byte ptr[ebx],al
	inc	ebx

;██████ DECREMENT COUNTER REGISTER █████████████████████████████████████████████████████████████

__make_inc:
	mov	al,4
	call	brandom32
	dec	eax
	je	__sub_1
	dec	eax
	je	__sub_2

	mov	al,48h				; dec creg
	or	al,byte ptr[ebp+creg]
	stosb

	mov	byte ptr[ebx],al
	inc	ebx

	jmp	__make_inc_exit
__sub_1:
	mov	ax,0E883h			; sub creg,1
	or	ah,byte ptr[ebp+creg]
	stosw

	mov	word ptr[ebx],ax
	inc	ebx
	inc	ebx

	mov	al,1
	stosb

	mov	byte ptr[ebx],al
	inc	ebx

	jmp	__make_inc_exit

__sub_2:
	mov	ax,0C083h			; add creg,-1
	or	ah,byte ptr[ebp+creg]
	stosw

	mov	word ptr[ebx],ax
	inc	ebx
	inc	ebx

	mov	al,-1
	stosb

	mov	byte ptr[ebx],al
	inc	ebx

	call	_gen_junks

__make_inc_exit:
	mov	ax,0C083h			; add preg,4
	or	ah,byte ptr[ebp+preg]
	mov	word ptr[ebx],ax
	inc	ebx
	inc	ebx
	mov	byte ptr[ebx],4
	inc	ebx

	mov	al,4
	call	brandom32
	dec	eax
	je	__inc_preg_1
	dec	eax
	je	__inc_preg_2

	mov	ax,0C083h			; add preg,4
	or	ah,byte ptr[ebp+preg]
	stosw
	mov	al,4
	stosb
	jmp	__test_counter

__inc_preg_1:
	call	_gen_junks

	mov	ax,0E883h			; sub preg,-4
	or	ah,byte ptr[ebp+preg]
	stosw
	mov	al,-4
	stosb
	jmp	__test_counter

__inc_preg_2:
	call	_gen_junks

	mov	al,8Dh				; lea preg,[preg+4]
	stosb

	mov	al,byte ptr[ebp+preg]
	shl	al,3
	or	al,byte ptr[ebp+preg]
	or	al,01000000b
	stosb

	mov	al,4
	stosb

__test_counter:
	call	_gen_junks

	mov	al,(_test_table_len/4)
	call	brandom32

	mov	eax,[ebp+eax*4+offset _test_table]
	lea	eax,[eax+ebp]
	jmp	eax

__test_0:
	call	_gen_junks

	mov	ax,0F883h			; cmp creg,0
	or	ah,byte ptr[ebp+creg]
	stosw
	sub	eax,eax
	stosb
	jmp	__test_counter_exit

__test_1:
	call	_gen_junks

	mov	al,85h
	stosb

	mov	al,byte ptr[ebp+creg]		; test creg,creg
	shl	al,3
	or	al,byte ptr[ebp+creg]
	or	al,11000000b

	stosb
	jmp	__test_counter_exit

__test_2:
	call	_gen_junks

	mov	al,8Bh
	stosb

	mov	al,byte ptr[ebp+jrg1]

	shl	al,3
	or	al,byte ptr[ebp+creg]		; mov jrg1,creg
	or	al,11000000b			; mov reg,reg
	stosb

	mov	ax,0F883h			; cmp jrg,0
	or	ah,byte ptr[ebp+jrg1]
	stosw
	sub	eax,eax
	stosb
	jmp	__test_counter_exit

__test_3:

	mov	al,50h
	or	al,byte ptr[ebp+creg]		; push creg
	stosb

	call	_gen_junks

	mov	al,58h				; pop jrg2
	or	al,byte ptr[ebp+jrg2]
	stosb

	mov	al,85h
	stosb

	mov	al,byte ptr[ebp+jrg2]		; test jrg2,jrg2
	shl	al,3
	or	al,byte ptr[ebp+jrg2]
	or	al,11000000b

	stosb

__test_counter_exit:

	mov	ax,0F883h			; cmp creg,0
	or	ah,byte ptr[ebp+creg]
	mov	word ptr[ebx],ax
	inc	ebx
	inc	ebx

	mov	byte ptr[ebx],0
	inc	ebx

	mov	ax,850Fh
	stosw

	mov	word ptr[ebx],ax
	inc	ebx
	inc	ebx

	mov	eax,12345678

__loop_here	equ dword ptr $-4

	sub	eax,edi
	sub	eax,4
	stosd					; jne	_decrypt_rest

	mov	eax,dword ptr[ebp+_spe32_encryptor]
	add	eax,6

	sub	eax,ebx

	mov	dword ptr[ebx],eax
	add	ebx,4

	call	_gen_junks

;██████ POP ALL REGISTERS ██████████████████████████████████████████████████████████████████████
__pop_regs:

	mov	edx,[ebp+_spe32_flags]

IFDEF REG_STATE
	test	edx,PRESERVE_REGS
	je	__check_rflags
	mov	al,61h
	stosb
__check_rflags:
	test	edx,PRESERVE_FLAGS
	je	__skip_restore_all
	mov	al,9Dh				; pushad,pushfd
	stosb
__skip_restore_all:
ENDIF

;	@bpx

	call	_debug_mode			; set int 3

	mov	byte ptr[ebx],0C3h		; ret

	mov	al,0E9h				; jmp decrypted_code
	stosb

	pop	eax				; eax pointer to code
	sub	eax,edi				; edi current position
	sub	eax,4				; size of jmp - 1
	stosd					; save it

	mov	ax,25FFh
	stosw

	stosd

	call	_gen_junks
;int 3
	pop	ebx
	call	ebx

	pop	eax
	sub	edi,eax
	xchg	edi,eax

	ret

;█ S U B R O U T I N E S ███████████████████████████████████████████████████████████████████████

brandom32 proc near

	push	edx
	and	eax,000000FFh			; al - param
	push	eax
	call	random32
	pop	ecx
	sub	edx,edx
	div	ecx
	xchg	eax,edx				; calc modulo n
	pop	edx

	ret

brandom32 endp

; WhizKid random num generator
random32 proc near

	push	edx
	push	ecx

	mov	eax,[ebp+offset _spe32_seed]	; Move bits 31-0 of old seed to EAX
						; Move bits 38-32 of old seed to DL, set DH = 0
	movzx	edx, byte ptr [ebp+offset _spe32_seed+4]
						; Shift bits 32-1 to bits 31-0
	shrd	eax, edx, 1
	mov	dword ptr[ebp+offset _spe32_seed], eax	; Save bits 31-0 of new seed
	adc	dh, 0				; DH = bit shifted out of EAX
	shr	dl, 1				; Shift bits 38-33 of old seed to bits 37-32
	mov	cl, dl				; Get bit 35 of old seed to the lsb of CL
	shr	cl, 2
	and	cl, 1				; CL = bit 35 of old seed
	xor	dh, cl				; xor it with old bit 0
	shl	dh, 6
	or	dl, dh				; store it in bit 38 ...
	mov	byte ptr [ebp+offset _spe32_seed+4],dl	; ... of new seed

	pop	ecx
	pop	edx
	ret

_spe32_seed	dd 987374832			; seed for random proc
		db 11101b			; at least one of the 39 bits must be non-zero!

random32 endp

_debug_mode proc near

	mov	edx,dword ptr[ebp+_spe32_flags]
	test	edx,DEBUG_MODE
	je	_skip_debug_mark

	@bpx

_skip_debug_mark:
	ret

_debug_mode endp

;██████ JUNK GEN ███████████████████████████████████████████████████████████████████████████████

_gen_junks proc near

IFDEF GEN_JUNKS
	push	ecx				; save global size of code

IFDEF JUNKS
	mov	al,JUNKS
__gen_junk_passes:
	call	brandom32
	xchg	eax,ecx
	jecxz	__gen_junk_passes

_gen_junks_loop:
	push	ecx
ENDIF

	mov	al,(_junk_table_len/4)
	call	brandom32

	mov	eax,[ebp+eax*4+offset _junk_table]
	lea	eax,[eax+ebp]
	jmp	eax
	
__junk_1 label near
	mov	al,81h
	stosb

	mov	al,3
	call	brandom32

	mov	al,byte ptr[ebp+eax*2+_crypt_opcodes]
	push	eax

	mov	al,2
	call	brandom32
	xchg	eax,ecx

	pop	eax

	jecxz	__junk_1_1	

	or	al,byte ptr[ebp+jrg1]
	jmp	__junk_1_2
__junk_1_1:
	or	al,byte ptr[ebp+jrg2]
__junk_1_2:
	stosb
	jmp	__junk_key
	
__junk_2 label near

__junk_3 label near
	mov	al,0E8h				; call $+7
	stosb

	mov	al,2
	call	brandom32

	test	eax,eax
	je	__call_2

	sub	eax,eax
	mov	al,2
	stosd

	mov	al,2
	call	brandom32
	xchg	eax,ecx
	jecxz	__junk_3_2

	mov	ax,9066h			; 32bit nop
	stosw
	jmp	__exit_from_call

__call_2:
	sub	eax,eax
	stosd
__junk_3_1:

	mov	al,0Bh				; range
	call	brandom32

	add	al,74h				; jxx $+3
	mov	ah,01h
	stosw

	call	random32
	and	eax,8
	
	add	al,40h				; inc,dec jreg1
	or	al,byte ptr[ebp+jrg1]
	stosb

	jmp	__exit_from_call
__junk_3_2:
	mov	ax,01EBh			; jmp $+3
	stosw

	mov	al,0C3h				; ret
	stosb
	jmp	__junk_gen_exit

__exit_from_call:

	mov	al,2
	call	brandom32
	test	eax,eax
	je	__exit_1_1			; select stack adjust method(pop or add esp)

	mov	ax,0C483h			; add esp,4
	stosw

	mov	al,04
	stosb
	jmp	__junk_gen_exit

__exit_1_1:

	mov	al,2
	call	brandom32
	xchg	eax,ecx

	mov	al,58h
	jecxz	__exit_1_1_1

	or	al,byte ptr[ebp+jrg1]		; pop jrg1
	jmp	__exit_1_1_2
__exit_1_1_1:
	or	al,byte ptr[ebp+jrg2]		; pop jrg2
__exit_1_1_2:
	stosb
	jmp	__junk_gen_exit

__junk_key:
	call	random32
	stosd
	jmp	__junk_gen_exit

__junk_4 label near
	mov	al,0E8h				; call $+6
	stosb

	sub	eax,eax
	inc	eax
	stosd

	call	random32
	stosb					; db trash
	jmp	__exit_from_call		; adjust stack

;█ MOV DRx,JRGx █████████████████████████████████████████████████████████████████████████████████
__junk_5 label near
;
;	mov	al,2
;	call	brandom32
;	xchg	eax,ecx
;
;	mov	al,0Fh
;
;	jecxz	__mov_drX_reg
;
;	mov	ah,23h				; mov drX,reg
;	jmp	__mov_reg_drX
;
;__mov_drX_reg:
;	mov	ah,21h				; mov reg,drX
;__mov_reg_drX:
;	stosw
;	mov	al,7				; select random drX
;	call	brandom32
;
;	shl	al,3
;	or	al,11000000b
;
;	push	eax
;
;	mov	al,2
;	call	brandom32
;	xchg	eax,ecx
;
;	pop	eax
;
;	jecxz	__mov_drX_jrg1
;
;	or	al,byte ptr[ebp+jrg2]
;	jmp	__mov_drX_jrg2
;__mov_drX_jrg1:
;	or	al,byte ptr[ebp+jrg1]
;__mov_drX_jrg2:
;	stosb

;█ JMP $+3 █████████████████████████████████████████████████████████████████████████████████████

__junk_6 label near

	mov	ax,02EBh			; jmp $+4
	stosw

	mov	al,2
	call	brandom32
	xchg	eax,ecx
	jecxz	__fake_vxdcall

	call	random32
	jmp	__skip_shit
__fake_vxdcall:
	mov	ax,20CDh			; VxDCall ???????
__skip_shit:
	stosw					; dw RND

	jmp	__junk_gen_exit

;█ FAKE MOV ████████████████████████████████████████████████████████████████████████████████████
; mov	jrg1,anyreg
; mov	jrg2,anyreg

__junk_7 label near

	mov	al,8Bh
	stosb

	mov	al,6
	call	brandom32

	mov	dl,byte ptr[ebp+eax+used_registers]

	mov	al,2
	call	brandom32

	xchg	eax,ecx
	jecxz	_use_jrg1
	
	mov	al,byte ptr[ebp+jrg2]
	jmp	_build_mov_jrg

_use_jrg1:

	mov	al,byte ptr[ebp+jrg1]

_build_mov_jrg:

	shl	al,3
	or	al,dl
	or	al,11000000b			; mov reg,reg
	stosb
	jmp	__junk_gen_exit

;█ Jxx $+2 █████████████████████████████████████████████████████████████████████████████████████

__junk_8 label near

	mov	al,0Bh
	call	brandom32

	add	al,74h				; jxx	$+2
	stosw

	jmp	__junk_gen_exit

;█ ROx,RCx,SHx JRG1,BYTE ████████████████████████████████████████████████████████████████████████

__junk_9 label near

	mov	al,0C1h
	stosb

	mov	al,_junk_opcodes_3_len
	call	brandom32
	push	eax

	call	random32
	and	eax,8

	pop	edx

	add	al,byte ptr[ebp+edx+_junk_opcodes_3]
	or	al,byte ptr[ebp+jrg1]
	stosb

	call	random32
	stosb

	jmp	__junk_gen_exit

;█ AND,OR,NEG,NOT JRG2, ANY ████████████████████████████████████████████████████████████████████

__junk_10 label near

	mov	al,_junk_opcodes_2_len
	call	brandom32

	mov	al,byte ptr[ebp+eax+_junk_opcodes_2]
	stosb

	mov	al,7
	call	brandom32
	xchg	eax,edx

	mov	al,byte ptr[ebp+jrg2]
	shl	al,3
	or	al,dl
	or	al,11000000b
	stosb

	jmp	__junk_gen_exit

;█ BT,BTR,BTS,BTC JRGX,ANY █████████████████████████████████████████████████████████████████████

__junk_11 label near

	mov	al,0Fh
	stosb

	mov	al,4
	call	brandom32

	mov	al,byte ptr[ebp+eax+__bt_opcodes]

__junk_11_end:
	stosb

	mov	al,7
	call	brandom32
	shl	al,3
	or	al,11000000b
	xchg	eax,edx
	
	mov	al,2
	call	brandom32
	xchg	eax,ecx
	jecxz	__junk_11_jrg1

	or	dl,byte ptr[ebp+jrg2]

	jmp	__junk_11_jrg2

__junk_11_jrg1:
	or	dl,byte ptr[ebp+jrg1]

__junk_11_jrg2:
	xchg	eax,edx
	stosb

	jmp	__junk_gen_exit

__junk_gen_exit:

IFDEF JUNKS
	pop	ecx
	dec	ecx
	jne	_gen_junks_loop
ENDIF
	pop	ecx
ENDIF
	ret
_gen_junks endp

IFDEF GEN_JUNKS

_junk_table	dd	offset __junk_1
		dd	offset __junk_2
		dd	offset __junk_3
		dd	offset __junk_3
		dd	offset __junk_4
		dd	offset __junk_5
		dd	offset __junk_6
		dd	offset __junk_7
		dd	offset __junk_8
		dd	offset __junk_9
		dd	offset __junk_10
		dd	offset __junk_11
_junk_table_len	equ $-_junk_table

; 3bytes
; prefix 0C1h
_junk_opcodes_3	db	0C0h			; rol,ror reg,byte
		db	0D0h			; rcl,rcr reg,byte
		db	0E0h			; shl,shr reg,byte
_junk_opcodes_3_len	equ $-_junk_opcodes_3

		db	0F7h,0D0h		; not reg
		db	0F7h,0D8h		; neg reg

__bt_opcodes	db	0A3h			; bt jrgx,any
		db	0ABh			; bts jrgx,any
		db	0B3h			; btr jrgx,any
		db	0BBh			; btc jrgx,any

; 2bytes
; MOD/R Cx
_junk_opcodes_2	db	03Bh			; cmp
		db	02Bh			; sub
		db	003h			; add
		db	01Bh			; sbb
		db	013h			; adc
		db	023h			; and
		db	00Bh			; or
_junk_opcodes_2_len	equ $-_junk_opcodes_2

ENDIF

_test_table	dd	offset __test_0
		dd	offset __test_1
		dd	offset __test_2
		dd	offset __test_3
_test_table_len	equ $-_test_table

_spe32_encryptor	dd 0
_spe32_flags		dd 0

used_registers	label near
	kreg	db	0			; key r
	preg	db	1			; pointer r
	creg	db	2			; counter r
	vreg	db	3			; value r
	jrg1	db	6			; junk reg 1
	jrg2	db	7			; junk reg 2

; 6bytes

_crypt_opcodes label near
	_sub	db	0E8h,0C0h
	_add	db	0C0h,0E8h
	_xor	db	0F0h,0F0h
_crypt_opcodes_len	equ $-_crypt_opcodes

SPE32 endp