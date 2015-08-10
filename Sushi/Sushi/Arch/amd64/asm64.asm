;
; This module implements all assembler code
;
include common.inc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN VmxVmExitHandler : PROC
EXTERN MiscDumpGpRegisters : PROC
EXTERN MiscWaitForever : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; constants
;
.CONST

VM_INSTRUCTION_ERROR        EQU     00004400h
VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

; Dumps all general purpose registers and a flag register.
ASM_DUMP_REGISTERS MACRO
    pushfq
    PUSHAQ
    mov rcx, rsp
    mov rdx, rsp
    add rdx, 8*17
    
    sub rsp, 28h
    call MiscDumpGpRegisters ; MiscDumpGpRegisters(GuestContext, rsp);
    add rsp, 28h
    
    POPAQ
    popfq
ENDM


; Implements jump to an arbitrary location without modifying registers.
; 0ffffffffffffffffh is used as a mark to be replaced with a correct address.
ASM_JMP_TEMPLATE MACRO 
    nop     ; This is space for implanting int 3 for debugging
    jmp     qword ptr [jmp_address]
jmp_address:
    dq      0ffffffffffffffffh
ENDM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE INIT

; EXTERN_C bool AsmInitialieVM(_In_ void(* VmInitializationRoutine)(
;     ULONG_PTR GuestStackPointer, ULONG_PTR GuestInstructionPointer));
; 
; A wrapper for VmInitializationRoutine.
AsmInitialieVM PROC
    pushfq
    PUSHAQ

    mov rax, rcx
    mov rdx, asmResumeVM
    mov rcx, rsp

    sub rsp, 28h
    call rax                ; VmInitializationRoutine(rsp, asmResumeVM)
    add rsp, 28h

    POPAQ
    popfq
    xor rax, rax            ; return false
    ret

    ; This is where the vitalized guest start to execute after successful 
    ; vmlaunch. 
asmResumeVM:
    POPAQ
    popfq

    ASM_DUMP_REGISTERS
    or rax, 1               ; return true
    ret
AsmInitialieVM ENDP


.CODE


; An entry point of VMM where gets called whenever VM-exit occurred.
AsmVmmEntryPoint PROC
    ; No need to save the flag registers since it is restored from the VMCS at
    ; the time of vmresume.
    PUSHAQ                  ; -8 * 16
    mov rcx, rsp
    
    sub rsp, 28h
    call VmxVmExitHandler   ; bool vmContinue = VmxVmExitHandler(GuestContext);
    add rsp, 28h

    test rax, rax
    jz exitVM               ; if (!vmContinue) jmp exitVM

    POPAQ
    vmresume
    int 3
    jz errorWithCode        ; if (ZF) jmp
    jmp errorWithoutCode 

    ; Executes vmxoff and ends virtualization
exitVM:
    ;   r8  = Guest's rflags
    ;   rdx = Guest's rsp
    ;   rcx = Guest's rip for the next instruction
    POPAQ
    vmxoff
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    push r8
    popfq                   ; rflags <= GurstFlags 
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn

errorWithCode:
    mov rcx, VM_INSTRUCTION_ERROR 
    vmread rcx, rcx

errorWithoutCode:
    jmp errorWithoutCode
AsmVmmEntryPoint ENDP


; EXTERN_C VMX_STATUS AsmVmxCall(_In_ ULONG_PTR HyperCallNumber,
;                                _In_opt_ void *Context);
;
; Executes vmcall with the given hypercall number and a context parameter.
AsmVmxCall PROC
    vmcall                  ; vmcall(HyperCallNumber, Context)
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmVmxCall ENDP


; GDT
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP

AsmReadGDT PROC
    sgdt [rcx]
    ret
AsmReadGDT ENDP


; LDTR
AsmWriteLDTR PROC
    lldt cx
    ret
AsmWriteLDTR ENDP

AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP


; TR
AsmWriteTR PROC
    ltr cx
    ret
AsmWriteTR ENDP

AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP


; ES
AsmWriteES PROC
    mov es, cx
    ret
AsmWriteES ENDP

AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP


; CS
AsmWriteCS PROC
    mov cs, cx
    ret
AsmWriteCS ENDP

AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP


; SS
AsmWriteSS PROC
    mov ss, cx
    ret
AsmWriteSS ENDP

AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP


; DS
AsmWriteDS PROC
    mov ds, cx
    ret
AsmWriteDS ENDP

AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP


; FS
AsmWriteFS PROC
    mov fs, cx
    ret
AsmWriteFS ENDP

AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP


; GS
AsmWriteGS PROC
    mov gs, cx
    ret
AsmWriteGS ENDP

AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP


; MISC

AsmLoadAccessRightsByte PROC
    lar rax, rcx
    ret
AsmLoadAccessRightsByte ENDP


AsmInvalidateInternalCaches PROC
    invd
    ret
AsmInvalidateInternalCaches ENDP


AsmWriteCR2 PROC
    mov cr2, rcx
    ret
AsmWriteCR2 ENDP


AsmUndefinedInstruction PROC
    ud2
    ret
AsmUndefinedInstruction ENDP


AsmXsetbv PROC
    mov rax, r8
    xsetbv      ; XCR[ECX] <= EDX:EAX;
    ret
AsmXsetbv ENDP


; Calls MiscWaitForever() which puts this thread sleep forever. 
AsmWaitForever PROC
    pushfq
    PUSHAQ
    mov rcx, rsp
    mov rdx, rsp
    add rdx, 8*17
    
    sub rsp, 28h
    call MiscWaitForever    ; Using jmp instead will cause bug check in a 
                            ; subsequent sleep function.
    add rsp, 28h
    
    POPAQ
    popfq
    int 3
    ret
AsmWaitForever ENDP


END
