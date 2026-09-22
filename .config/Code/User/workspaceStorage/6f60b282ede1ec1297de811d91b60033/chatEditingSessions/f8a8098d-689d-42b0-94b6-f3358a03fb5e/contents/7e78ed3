import socket
import struct

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.x86_const import *


HOST = "43.203.148.171"
PORT = 31337
BASE = 0x1000000
STACK = 0x2000000
STACK_SIZE = 0x200000
PAGE = 0x1000


def align_up(value, alignment=PAGE):
    return (value + alignment - 1) & ~(alignment - 1)


def fetch_blob():
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    length = struct.unpack("<I", sock.recv(4))[0]
    blob = bytearray()
    while len(blob) < length:
        chunk = sock.recv(length - len(blob))
        if not chunk:
            break
        blob.extend(chunk)
    sock.close()
    return bytes(blob)


def decrypt_stage(blob):
    stage = bytearray(blob)
    start = 0x31
    count = 0x18FF8
    count = min(count, len(stage) - start)
    for index in range(1, count):
        stage[start + index] = (stage[start + index] + stage[start + index - 1]) & 0xFF
    for index in range(count):
        stage[start + index] ^= 0xA3
    return bytes(stage)


class Emulator:
    def __init__(self, code, stdin_data=b""):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.code = code
        self.stdin = bytearray(stdin_data)
        self.stdout = bytearray()
        self.next_mmap = 0x3000000
        self.mu.mem_map(BASE, align_up(len(code)), 7)
        self.mu.mem_write(BASE, code)
        self.mu.mem_map(STACK, STACK_SIZE, 7)
        self.mu.reg_write(UC_X86_REG_RSP, STACK + STACK_SIZE - 0x10)
        self.mu.reg_write(UC_X86_REG_RBP, STACK + STACK_SIZE - 0x10)
        self.mu.reg_write(UC_X86_REG_RIP, BASE)
        self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)

    def _read_mem(self, addr, size):
        return bytes(self.mu.mem_read(addr, size))

    def _write_mem(self, addr, data):
        self.mu.mem_write(addr, data)

    def _hook_code(self, uc, address, size, user_data):
        insn = self._read_mem(address, size)
        if insn == b"\x0f\x05":
            self._handle_syscall()

    def _handle_syscall(self):
        rax = self.mu.reg_read(UC_X86_REG_RAX)
        rdi = self.mu.reg_read(UC_X86_REG_RDI)
        rsi = self.mu.reg_read(UC_X86_REG_RSI)
        rdx = self.mu.reg_read(UC_X86_REG_RDX)
        r10 = self.mu.reg_read(UC_X86_REG_R10)

        if rax == 0:  # read
            if rdi == 0:
                count = min(rdx, len(self.stdin))
                data = bytes(self.stdin[:count])
                del self.stdin[:count]
                self._write_mem(rsi, data)
                self.mu.reg_write(UC_X86_REG_RAX, count)
            else:
                self.mu.reg_write(UC_X86_REG_RAX, 0)
        elif rax == 1:  # write
            data = self._read_mem(rsi, rdx)
            self.stdout.extend(data)
            print(data.decode("utf-8", "replace"), end="")
            self.mu.reg_write(UC_X86_REG_RAX, rdx)
        elif rax == 9:  # mmap
            addr = rdi
            length = rsi
            if addr == 0:
                addr = align_up(self.next_mmap)
                self.next_mmap = addr + align_up(length)
            self.mu.mem_map(addr, align_up(length), 7)
            self.mu.reg_write(UC_X86_REG_RAX, addr)
        elif rax in (10, 11, 12, 3, 41, 42, 44, 45):
            self.mu.reg_write(UC_X86_REG_RAX, 0)
        elif rax in (60, 231):
            raise SystemExit(rdi)
        else:
            print(f"[syscall {rax}] rdi={rdi:#x} rsi={rsi:#x} rdx={rdx:#x} r10={r10:#x}")
            self.mu.reg_write(UC_X86_REG_RAX, 0)

        self.mu.reg_write(UC_X86_REG_RIP, self.mu.reg_read(UC_X86_REG_RIP) + 2)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        rip = self.mu.reg_read(UC_X86_REG_RIP)
        print(f"[mem invalid] access={access} addr={address:#x} size={size} value={value:#x} rip={rip:#x}")
        page = address & ~(PAGE - 1)
        try:
            self.mu.mem_map(page, PAGE, 7)
            print(f"[mem mapped] {page:#x}")
            return True
        except Exception as exc:
            print(f"[mem map failed] {type(exc).__name__}: {exc}")
            return False

    def run(self, max_insns=2_000_000):
        try:
            self.mu.emu_start(BASE, BASE + len(self.code), count=max_insns)
        except SystemExit as exc:
            print(f"[exit {exc.code}]")
        except Exception as exc:
            print(f"[emu error] {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    blob = fetch_blob()
    stage = decrypt_stage(blob)
    for candidate in [b"\n", b"A\n", b"0\n", b"test\n"]:
        print(f"=== trying {candidate!r} ===")
        emu = Emulator(stage, stdin_data=candidate)
        emu.run()
        print()