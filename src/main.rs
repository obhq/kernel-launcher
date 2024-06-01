#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use okf::ext::KernelExt;
use okf::lock::Mtx;
use okf::pcpu::Pcpu;
use okf::socket::{InAddr, SockAddrIn, Socket, AF_INET, SOCK_STREAM};
use okf::{kernel, Kernel};

// The job of this custom entry point is:
//
// - Get address where our payload is loaded.
// - Do ELF relocation on our payload.
global_asm!(
    ".globl _start",
    ".section .text.startup",
    "_start:",
    "lea rdi, [rip]",
    "sub rdi, 7", // 7 is size of "lea rdi, [rip]".
    "mov rax, rdi",
    "add rax, 0x80", // Offset of dynamic section configured in linker script.
    "xor r8, r8",
    "0:",
    "mov rsi, [rax]",
    "mov rcx, [rax+8]",
    "add rax, 16",
    "test rsi, rsi", // Check if DT_NULL.
    "jz 1f",
    "cmp rsi, 7", // Check if DT_RELA.
    "jz 2f",
    "cmp rsi, 8", // Check if DT_RELASZ.
    "jz 3f",
    "jmp 0b",
    "2:", // Keep DT_RELA.
    "mov rdx, rdi",
    "add rdx, rcx",
    "jmp 0b",
    "3:", // Keep DT_RELASZ.
    "mov r8, rcx",
    "jmp 0b",
    "1:",
    "test r8, r8", // Check if no more DT_RELA entries.
    "jz main",
    "mov rsi, [rdx]",
    "mov rax, [rdx+8]",
    "mov rcx, [rdx+16]",
    "add rdx, 24",
    "sub r8, 24",
    "test eax, eax", // Check if R_X86_64_NONE.
    "jz main",
    "cmp eax, 8", // Check if R_X86_64_RELATIVE.
    "jnz 1b",
    "add rsi, rdi",
    "add rcx, rdi",
    "mov [rsi], rcx",
    "jmp 1b",
);

#[no_mangle]
extern "C" fn main(_: *const u8) {
    run(<kernel!()>::default());
}

fn run<K: Kernel>(k: K) {
    // Create server socket.
    let td = K::Pcpu::curthread();
    let server = unsafe { k.socket(AF_INET, SOCK_STREAM, 0, td).unwrap() };
    let server = server.as_raw();

    // Set server address.
    let mut addr = SockAddrIn::new(InAddr::ANY, 9020);

    unsafe { k.bind(server, addr.as_mut(), td).unwrap() };
    unsafe { k.listen(server, 1, td).unwrap() };

    // Wait for a connection.
    let mtx = k.var(K::ACCEPT_MTX).ptr();

    unsafe {
        k.mtx_lock_flags(
            mtx,
            0,
            c"W:\\Build\\J02650690\\sys\\freebsd\\sys\\kern\\uipc_syscalls.c".as_ptr(),
            666,
        )
    };

    loop {
        // Check if error.
        if unsafe { (*server).error() != 0 } {
            unsafe { (*server).set_error(0) };
        } else {
        }

        // Wait for socket events.
        let error = unsafe {
            k.sleep(
                (*server).timeout().cast(),
                (*mtx).lock_mut(),
                0x1058,
                c"accept".as_ptr(),
                0,
            )
        };

        assert_eq!(error, 0);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // Nothing to do here since we enabled panic_immediate_abort.
    loop {}
}
