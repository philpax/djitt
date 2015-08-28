import std.bitmanip;
import std.algorithm;
import std.string;
import std.array;
import std.stdio;
import std.traits;

struct Reg(int Size)
{
    ubyte index;
}

alias Reg8 = Reg!8;
alias Reg16 = Reg!16;
alias Reg32 = Reg!32;
alias Reg64 = Reg!64;

enum AL = Reg8(0);
enum CL = Reg8(1);
enum DL = Reg8(2);
enum BL = Reg8(3);
enum AH = Reg8(4);
enum CH = Reg8(5);
enum DH = Reg8(6);
enum BH = Reg8(7);

enum AX = Reg16(0);
enum CX = Reg16(1);
enum DX = Reg16(2);
enum BX = Reg16(3);
enum SP = Reg16(4);
enum BP = Reg16(5);
enum SI = Reg16(6);
enum DI = Reg16(7);

enum EAX = Reg32(0);
enum ECX = Reg32(1);
enum EDX = Reg32(2);
enum EBX = Reg32(3);
enum ESP = Reg32(4);
enum EBP = Reg32(5);
enum ESI = Reg32(6);
enum EDI = Reg32(7);

enum RAX = Reg64(0);
enum RCX = Reg64(1);
enum RDX = Reg64(2);
enum RBX = Reg64(3);
enum RSP = Reg64(4);
enum RBP = Reg64(5);
enum RSI = Reg64(6);
enum RDI = Reg64(7);

enum Mode
{
    Memory,
    MemoryOffset8,
    MemoryOffsetExt,
    Register
}

union ModRM
{
    static ModRM opCall(int Size)(
        Reg!Size register1, Reg!Size register2, Mode mod = Mode.Register)
    {
        ModRM modRM;
        modRM.register1 = register1.index;
        modRM.register2 = register2.index;
        modRM.mod = cast(ubyte)mod;
        return modRM;
    }

    struct
    {
        mixin(bitfields!(
            ubyte,  "register1",    3,
            ubyte,  "register2",    3,
            ubyte,  "mod",          2,
        ));
    }
    ubyte b;

    alias b this;
}

static assert(ModRM.sizeof == 1);

struct MemoryAccess(int Size)
{
    ubyte register;
    int offset = 0;

    this(Register)(Register register, int offset = 0)
    {
        this.register = register.index;
        this.offset = offset;
    }
}

struct LabelRelocation
{
    size_t location;
    string label;
    bool signExtend;
}

struct GenericRelocation
{
    this(size_t location, const(void*) destination, bool signExtend)
    {
        this.location = location;
        this.destination = destination;
        this.signExtend = signExtend;

        // Assume that this instruction ends after this relocation
        this.relativeToLocation = this.location + (signExtend ? 8 : 4);
    }

    size_t location;
    size_t relativeToLocation;
    const(void*) destination;
    bool signExtend;
}

bool fitsIn(T, Y)(Y value)
{
    return value >= T.min && value <= T.max;
}

struct Block
{
    void emit(int b)
    {
        this.buffer_ ~= cast(ubyte)b;
    }

    void emitImmediate(T)(T val)
    {
        import core.stdc.string : memcpy;
        const size = T.sizeof;

        this.buffer_.length += size;
        memcpy(&this.buffer_[$-size], &val, size);
    }

    void emitLabelRelocation(string name, bool signExtend = false)
    {
        version (X86)
            signExtend = false;

        void emitRelocation(Type)()
        {
            this.labelRelocations_ ~=
                LabelRelocation(this.buffer_.length, name, signExtend);
            this.emitImmediate!Type(0x00);
        }

        if (signExtend)
            emitRelocation!ulong();
        else
            emitRelocation!uint();
    }

    void emitGenericRelocation(void* destination, bool signExtend = false)
    {
        version (X86)
            signExtend = false;

        void emitRelocation(Type)()
        {
            this.genericRelocations_ ~=
                GenericRelocation(this.buffer_.length, destination, signExtend);
            this.emitImmediate!Type(0x00);
        }

        if (signExtend)
            emitRelocation!ulong();
        else
            emitRelocation!uint();
    }

    void emitRegisterMemoryAccess(Register, MemoryAccess)(Register r1, MemoryAccess r2)
    {
        if (r2.offset)
        {
            if (r2.offset.fitsIn!byte)
            {
                this.emit(ModRM(Register(r2.register), r1, Mode.MemoryOffset8));
                this.emitImmediate(cast(byte)r2.offset);
            }
            else
            {
                this.emit(ModRM(Register(r2.register), r1, Mode.MemoryOffsetExt));
                this.emitImmediate(r2.offset);
            }
        }
        else
        {
            this.emit(ModRM(Register(r2.register), r1, Mode.Memory));
        }
    }

    void emitRexW()
    {
        version (X86_64)
        {
            this.emit(0x48);
        }
    }

    // Arithmetic
    void add(Reg32 destination, Reg32 source)
    {
        this.emit(0x01);
        this.emit(ModRM(destination, source));
    }

    void add(Reg8 destination, byte immediate)
    {
        if (destination == AL)
        {
            this.emit(0x04);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x80);
            // Write 0 to select 0x80 /0 (add r/m8, i8)
            this.emit(ModRM(destination, Reg8(0)));
            this.emitImmediate(immediate);
        }
    }

    void add(Reg32 destination, uint immediate)
    {
        if (destination == EAX)
        {
            this.emit(0x05);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x81);
            // Write 0 to select 0x81 /0 (add r/m32, i32)
            this.emit(ModRM(destination, Reg32(0)));
            this.emitImmediate(immediate);
        }
    }

    void add(Reg64 destination, uint immediate)
    {
        this.emitRexW();
        this.add(Reg32(destination.index), immediate);
    }

    void add(MemoryAccess!32 destination, uint immediate)
    {
        this.emit(0x81);
        // Write 0 to select 0x81 /0 (add r/m32, i32)
        this.emitRegisterMemoryAccess(Reg32(0), destination);
        this.emitImmediate(immediate);
    }

    void add(MemoryAccess!8 destination, byte immediate)
    {
        this.emit(0x80);
        // Write 0 to select 0x80 /0 (add r/m8, i8)
        this.emitRegisterMemoryAccess(Reg8(0), destination);
        this.emitImmediate(immediate);
    }

    void sub(MemoryAccess!8 destination, byte immediate)
    {
        this.emit(0x80);
        // Write 5 to select 0x80 /5 (sub r/m8, i8)
        this.emitRegisterMemoryAccess(Reg8(5), destination);
        this.emitImmediate(immediate);
    }

    void sub(Reg8 destination, byte immediate)
    {
        if (destination == AL)
        {
            this.emit(0x2C);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x80);
            // Write 5 to select 0x80 /5 (sub r/m8, i8)
            this.emit(ModRM(destination, Reg8(5)));
            this.emitImmediate(immediate);
        }
    }

    void sub(Reg32 destination, uint immediate)
    {
        if (destination == EAX)
        {
            this.emit(0x2D);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x81);
            // Write 5 to select 0x81 /5 (sub r/m32, i32)
            this.emit(ModRM(destination, Reg32(5)));
            this.emitImmediate(immediate);
        }
    }

    void sub(Reg64 destination, uint immediate)
    {
        this.emitRexW();
        this.sub(Reg32(destination.index), immediate);
    }

    void inc(Reg32 destination)
    {
        version (X86_64)
        {
            this.emit(0xFF);

            // Write 0 to select 0xFF /0 (inc r/m)
            this.emit(ModRM(destination, Reg32(0)));
        }
        else
        {
            // inc eax -> edi
            this.emit(0x40 + destination.index);
        }
    }

    void inc(Reg64 destination)
    {
        this.emitRexW();
        this.inc(Reg32(destination.index));
    }

    void inc(MemoryAccess!8 destination)
    {
        this.emit(0xFE);
        this.emitRegisterMemoryAccess(Reg8(0), destination);
    }

    void inc(MemoryAccess!32 destination)
    {
        this.emit(0xFF);
        this.emitRegisterMemoryAccess(Reg32(0), destination);
    }

    void dec(Reg32 destination)
    {
        version (X86_64)
        {
            this.emit(0xFF);

            // Write 1 to select 0xFF /1 (dec r/m)
            this.emit(ModRM(destination, Reg32(1)));
        }
        else
        {
            // dec eax -> edi
            this.emit(0x48 + destination.index);
        }
    }

    void dec(Reg64 destination)
    {
        this.emitRexW();
        this.dec(Reg32(destination.index));
    }

    void dec(MemoryAccess!8 destination)
    {
        this.emit(0xFE);
        this.emitRegisterMemoryAccess(Reg8(1), destination);
    }

    void dec(MemoryAccess!32 destination)
    {
        this.emit(0xFF);
        this.emitRegisterMemoryAccess(Reg32(1), destination);
    }

    void xor(Reg32 destination, Reg32 source)
    {
        this.emit(0x31);
        this.emit(ModRM(destination, source));
    }

    void xor(Reg64 destination, Reg64 source)
    {
        this.emitRexW();
        this.xor(Reg32(destination.index), Reg32(source.index));
    }

    // Memory
    void push(Reg32 register)
    {
        // push eax -> edi
        this.emit(0x50 + register.index);
    }

    void push(Reg64 register)
    {
        this.push(Reg32(register.index));
    }

    void pop(Reg32 register)
    {
        // pop eax -> edi
        this.emit(0x58 + register.index);
    }

    void pop(Reg64 register)
    {
        this.pop(Reg32(register.index));
    }

    void mov(Reg32 destination, Reg32 source)
    {
        // mov reg, reg
        this.emit(0x8B);
        this.emit(ModRM(source, destination));
    }

    void mov(Reg64 destination, Reg64 source)
    {
        // mov reg, reg
        this.emitRexW();
        this.emit(0x8B);
        this.emit(ModRM(source, destination));
    }

    void mov(MemoryAccess!32 destination, Reg32 source)
    {
        // mov [reg+disp], reg
        this.emit(0x89);
        this.emitRegisterMemoryAccess(source, destination);
    }

    void mov(Reg8 destination, MemoryAccess!8 source)
    {
        // mov reg8, byte ptr [reg+disp]
        this.emit(0x8A);
        this.emitRegisterMemoryAccess(destination, source);
    }

    void mov(MemoryAccess!8 destination, Reg8 source)
    {
        // mov byte ptr [reg+disp], reg8
        this.emit(0x88);
        this.emitRegisterMemoryAccess(source, destination);
    }

    void mov(Reg32 destination, MemoryAccess!32 source)
    {
        // mov reg, dword ptr [reg+disp]
        this.emit(0x8B);
        this.emitRegisterMemoryAccess(destination, source);
    }

    void mov(Reg32 destination, uint immediate)
    {
        // mov reg, imm32
        this.emit(0xB8 + destination.index);
        this.emitImmediate(immediate);
    }

    void mov(Reg64 destination, ulong immediate)
    {
        // mov reg, imm64
        this.emitRexW();
        this.emit(0xB8 + destination.index);
        this.emitImmediate(immediate);
    }

    void mov(Register, Function)(Register destination, Function func)
        if (isFunctionPointer!Function)
    {
        this.mov(destination, cast(size_t)func);
    }

    void mov(MemoryAccess!8 destination, byte immediate)
    {
        this.emit(0xC6);
        // Write 0 to select 0xC6 /0 (mov r/m8, i8)
        this.emitRegisterMemoryAccess(Reg8(0), destination);
        this.emitImmediate(immediate);
    }

    void mov(MemoryAccess!32 destination, uint immediate)
    {
        this.emit(0xC7);
        // Write 0 to select 0xC7 /0 (mov r/m32, i32)
        this.emitRegisterMemoryAccess(Reg32(0), destination);
        this.emitImmediate(immediate);
    }

    void cmp(Reg8 source, ubyte immediate)
    {
        if (source == AL)
        {
            this.emit(0x3C);
            this.emit(immediate);
        }
        else
        {
            this.emit(0x80);
            // 0x80 /7 (cmp r/m8, i8)
            this.emit(ModRM(source, Reg8(7)));
        }
    }

    void cmp(Reg32 source, uint immediate)
    {
        if (source == EAX)
        {
            this.emit(0x3D);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x81);
            // Write 7 to select 0x81 /7 (cmp r/m32, i32)
            this.emit(ModRM(source, Reg32(7)));
            this.emitImmediate(immediate);
        }
    }

    void cmp(Reg64 source, uint immediate)
    {
        this.emitRexW();
        this.cmp(Reg32(source.index), immediate);
    }

    void cmp(MemoryAccess!8 destination, byte immediate)
    {
        this.emit(0x80);
        // Write 7 to select 0x80 /7 (cmp r/m8, i8)
        this.emitRegisterMemoryAccess(Reg8(7), destination);
        this.emitImmediate(immediate);
    }

    // Control flow
    void jmp(string name)
    {
        this.emit(0xE9);
        this.emitLabelRelocation(name, true);
    }

    void je(string name)
    {
        this.emit(0x0F);
        this.emit(0x84);
        this.emitLabelRelocation(name);
    }

    void jne(string name)
    {
        this.emit(0x0F);
        this.emit(0x85);
        this.emitLabelRelocation(name);
    }

    void call(void* destination)
    {
        this.emit(0xE8);
        this.emitGenericRelocation(destination);
    }

    void call(int Size)(Reg!Size destination)
        if (Size >= 32)
    {
        this.emit(0xFF);
        // Write 2 to select call r/m (0xFF /2)
        this.emit(ModRM(destination, Reg!Size(2)));
    }

    void label(string name)
    {
        this.labels_[name] = this.buffer_.length - 1;
    }

    void ret()
    {
        this.emit(0xC3);
    }

    void int_(ubyte code)
    {
        if (code == 3)
            this.emit(0xCC);
        else
            assert(false);
    }

    // Forwards to constructor for convenience in `with` blocks
    MemoryAccess!8 bytePtr(Args...)(Args args)
    {
        return MemoryAccess!8(args);
    }

    MemoryAccess!32 dwordPtr(Args...)(Args args)
    {
        return MemoryAccess!32(args);
    }

    MemoryAccess!64 qwordPtr(Args...)(Args args)
    {
        return MemoryAccess!64(args);
    }

    void dump()
    {
        this.buffer_.map!(a => "%.2X".format(a)).join(" ").writeln();
    }

private:
    ubyte[] buffer_;
    LabelRelocation[] labelRelocations_;
    GenericRelocation[] genericRelocations_;
    size_t[string] labels_;
}

struct Assembly
{
    this(Block[] blocks...)
    {
        this.blocks_ = blocks.dup;
    }

    ~this()
    {
        version (Windows)
        {
            import std.c.windows.windows;

            if (this.finalBuffer_)
                VirtualFree(this.finalBuffer_, 0, MEM_RELEASE);
        }
        else version (linux)
        {
            import core.sys.posix.sys.mman;

            if (this.finalBuffer_)
                munmap(this.finalBuffer_, this.buffer_.length);
        }
    }

    void finalize()
    {
        size_t baseAddress = 0;

        // Build up the byte buffer and labels
        foreach (block; this.blocks_)
        {
            // Join block buffer with the assembly's buffer
            this.buffer_ ~= block.buffer_;

            // Copy the labels to the assembly, offsetting them as we go along
            foreach (key, value; block.labels_)
                this.labels_[key] = value + baseAddress;

            // Copy the relocations to the assembly, offseting them as we go along
            foreach (relocation; block.labelRelocations_)
            {
                relocation.location += baseAddress;
                this.labelRelocations_ ~= relocation;
            }

            // Copy the relocations to the assembly, offseting them as we go along
            foreach (relocation; block.genericRelocations_)
            {
                relocation.location += baseAddress;
                this.genericRelocations_ ~= relocation;
            }

            // Update the new base address
            baseAddress += block.buffer_.length;
        }

        // Copy into the final memory buffer, with privileges
        import std.c.string;
        version (Windows)
        {
            import std.c.windows.windows;

            this.finalBuffer_ = cast(ubyte*)VirtualAlloc(
                null, this.buffer_.length, MEM_COMMIT, PAGE_READWRITE);
        }
        else version (linux)
        {
            import core.sys.linux.sys.mman;
        
            this.finalBuffer_ = cast(ubyte*)mmap(
                null, this.buffer_.length, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

            assert(this.finalBuffer_);
        }

        memcpy(this.finalBuffer_, this.buffer_.ptr, this.buffer_.length);

        // Do relocations
        void writeInteger(Offset)(size_t location, Offset offset, bool signExtend)
        {
            if (signExtend)
                *cast(long*)&this.finalBuffer_[location] = offset;
            else
                *cast(int*)&this.finalBuffer_[location] = cast(int)offset;
        }

        import std.traits : Signed;
        foreach (const relocation; this.labelRelocations_)
        {
            auto location = relocation.location + 3;
            alias SignedType = Signed!size_t;
            auto offset = cast(SignedType)(this.labels_[relocation.label] - location);

            writeInteger(relocation.location, offset, relocation.signExtend);
        }

        foreach (const relocation; this.genericRelocations_)
        {
            auto location = relocation.location + this.finalBuffer_ + 4;
            alias SignedType = Signed!size_t;
            auto offset = cast(SignedType)(relocation.destination - location);

            writeInteger(relocation.location, offset, relocation.signExtend);
        }
    }

    void dump()
    {
        this.buffer.map!(a => "%.2X".format(a)).join(" ").writeln();
    }

    @property const(ubyte[]) buffer()
    {
        if (this.finalBuffer_)
            return this.finalBuffer_[0..this.buffer_.length];
        else
            return this.buffer_;
    }

    T call(T = void, Args...)(Args args)
    {
        extern (C) T function(Args) fn;

        assert(this.finalBuffer_ != null);

        // Provide execute privileges to buffer
        version (Windows)
        {
            import std.c.windows.windows;
            DWORD old;

            auto length = this.buffer_.length;
            VirtualProtect(this.finalBuffer_, length, PAGE_EXECUTE, &old);

            scope (exit)
                VirtualProtect(this.finalBuffer_, length, old, &old);
        }
        else version (linux)
        {
            import core.sys.posix.sys.mman;

            auto length = this.buffer_.length;
            mprotect(this.finalBuffer_, length, PROT_EXEC);

            scope (exit)
                mprotect(this.finalBuffer_, length, PROT_READ|PROT_WRITE);
        }

        fn = cast(typeof(fn))this.finalBuffer_;
        return fn(args);
    }

    void opCall(Args...)(Args args)
    {
        this.call(args);
    }

private:
    Block[] blocks_;
    ubyte[] buffer_;
    ubyte* finalBuffer_;
    size_t[string] labels_;
    LabelRelocation[] labelRelocations_;
    GenericRelocation[] genericRelocations_;
}

unittest
{
    writeln("Test: basic functionality");
    Block block;

    static char[] testBuffer;
    static void putchar_test(int c)
    {
        testBuffer ~= c;
    }

    version (X86_64)
        alias PutcharRegister = RBX;
    else
        alias PutcharRegister = EBX;

    with (block)
    {
        push(EBP);
        mov(EBP, ESP);

        push(PutcharRegister);
        mov(PutcharRegister, &putchar_test);
        xor(EAX, EAX);

        label("LOOP");
        mov(ECX, EAX);
        add(ECX, 65);

        // Call putchar, and clean up stack
        push(EAX);
        version (X86_64)
        {
            push(RCX);
            version (Posix)
            {
                mov(RDI, RCX);
                call(PutcharRegister);
            }
            else version (Windows)
            {
                sub(RSP, 32);
                call(PutcharRegister);
                add(RSP, 32);
            }
            pop(RCX);
        }
        else
        {
            push(PutcharRegister);
            mov(EAX, ECX);
            call(PutcharRegister);
            pop(PutcharRegister);
        }
        pop(EAX);

        inc(EAX);

        cmp(EAX, 26);
        jne("LOOP");

        pop(PutcharRegister);
        pop(EBP);
        ret;
    }

    auto assembly = Assembly(block);
    assembly.finalize();
    assembly.dump();

    const expectedOutput = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    assembly();
    writeln("Expected output: ", expectedOutput);
    writeln("Actual output: ", testBuffer);
    assert(expectedOutput == testBuffer);
    writeln();
}

unittest
{
    writeln("Test: mov reg, [reg+offset]");
    Block block;

    with (block)
    {
        push(EBP);
        mov(EBP, ESP);
        version (X86_64)
        {
            version (Posix)
                mov(EAX, EDI);
            else version (Windows)
                mov(EAX, ECX);
        }
        else
            mov(EAX, dwordPtr(EBP, 8));
        add(EAX, 5);
        pop(EBP);
        ret;
    }

    auto assembly = Assembly(block);
    assembly.finalize();
    assembly.dump();

    const expectedOutput = 10;
    auto result = assembly.call!int(5);
    writeln("Expected output: ", expectedOutput);
    writeln("Actual output: ", result);
    assert(expectedOutput == result);
    writeln();
}

unittest
{
    writeln("Test: add/sub byte ptr [reg], i8");
    Block block;

    version (X86_64)
        alias ArrayRegister = RDX;
    else
        alias ArrayRegister = EDX;

    with (block)
    {
        push(EBP);
        mov(EBP, ESP);

        // Load array into EDX
        version (X86_64)
        {
            version (Posix)
                mov(ArrayRegister, RDI);
            else version (Windows)
                mov(ArrayRegister, RCX);
        }
        else
            mov(ArrayRegister, dwordPtr(EBP, 8));
        // array[0] += 5
        add(bytePtr(ArrayRegister), 5);
        // Move to array[1]
        inc(ArrayRegister);
        // array[1] += 10
        add(bytePtr(ArrayRegister), 10);
        // Move to array[2]
        inc(ArrayRegister);
        // array[2] -= 10
        sub(bytePtr(ArrayRegister), 10);

        pop(EBP);
        ret;
    }

    auto assembly = Assembly(block);
    assembly.finalize();
    assembly.dump();

    byte[4] array;
    assembly(array.ptr);

    const expectedOutput = [5, 10, -10, 0];
    writeln("Expected output: ", expectedOutput);
    writeln("Actual output: ", array);
    assert(expectedOutput == array);
    writeln();
}