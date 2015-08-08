import std.bitmanip;
import std.algorithm;
import std.string;
import std.array;
import std.stdio;

enum Register
{
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
}

union ModRM
{
    static ModRM opCall(Register register1, Register register2, ubyte mod = 3)
    {
        ModRM modRM;
        modRM.register1 = register1;
        modRM.register2 = register2;
        modRM.mod = mod;
        return modRM;
    }

    struct
    {
        mixin(bitfields!(
            Register,   "register1",    3,
            Register,   "register2",    3,
            ubyte,      "mod",          2,
        ));
    }
    ubyte b;

    alias b this;
}

static assert(ModRM.sizeof == 1);

enum OperandType
{
    Byte,
    Word,
    DWord,
    QWord
}

struct MemoryAccess
{
    OperandType type = OperandType.DWord;
    Register register;
    int offset = 0;

    this(OperandType type, Register register, int offset = 0)
    {
        this.type = type;
        this.register = register;
        this.offset = offset;
    }

    this(Register register, int offset = 0)
    {
        this.register = register;
        this.offset = offset;
    }
}

struct LabelRelocation
{
    size_t location;
    string label;
}

struct GenericRelocation
{
    this(size_t location, const(void*) destination)
    {
        this.location = location;
        this.destination = destination;

        // Assume that this instruction ends 4 bytes after the relocation source
        this.relativeToLocation = this.location + 4;
    }

    size_t location;
    size_t relativeToLocation;
    const(void*) destination;
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

    void emitLabelRelocation(string name)
    {
        this.emitImmediate!uint(0x00);
        this.labelRelocations_ ~= LabelRelocation(this.buffer_.length - 4, name);        
    }

    void emitGenericRelocation(void* destination)
    {
        this.emitImmediate!uint(0x00);
        this.genericRelocations_ ~= GenericRelocation(this.buffer_.length - 4, destination);        
    }

    void emitRegisterMemoryAccess(Register r1, MemoryAccess r2)
    {
        if (r2.offset)
        {
            if (r2.offset.fitsIn!byte)
            {
                this.emit(ModRM(r2.register, r1, 1));
                this.emitImmediate(cast(byte)r2.offset);
            }
            else
            {
                this.emit(ModRM(r2.register, r1, 2));
                this.emitImmediate(r2.offset);
            }
        }
        else
        {
            this.emit(ModRM(r2.register, r1, 0));
        }
    }

    // Arithmetic
    void add(Register destination, Register source)
    {
        this.emit(0x01);
        this.emit(ModRM(destination, source));
    }

    void add(Register destination, byte immediate)
    {
        if (destination == Register.EAX)
        {
            this.emit(0x04);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x80);
            // Write 0 to select 0x80 /0 (add r/m8, i8)
            this.emit(ModRM(destination, cast(Register)0));
            this.emitImmediate(immediate);
        }
    }

    void add(Register destination, uint immediate)
    {
        if (destination == Register.EAX)
        {
            this.emit(0x05);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x81);
            // Write 0 to select 0x81 /0 (add r/m32, i32)
            this.emit(ModRM(destination, cast(Register)0));
            this.emitImmediate(immediate);
        }
    }

    void add(MemoryAccess destination, uint immediate)
    {
        if (destination.type == OperandType.DWord)
        {
            this.emit(0x81);
            // Write 0 to select 0x81 /0 (add r/m32, i32)
            this.emitRegisterMemoryAccess(cast(Register)0, destination);
            this.emitImmediate(immediate);
        }
    }

    void add(MemoryAccess destination, byte immediate)
    {
        if (destination.type == OperandType.Byte)
        {
            this.emit(0x80);
            // Write 0 to select 0x80 /0 (add r/m8, i8)
            this.emitRegisterMemoryAccess(cast(Register)0, destination);
            this.emitImmediate(cast(byte)immediate);
        }
        else
            assert(false);
    }

    void sub(MemoryAccess destination, byte immediate)
    {
        if (destination.type == OperandType.Byte)
        {
            this.emit(0x80);
            // Write 5 to select 0x80 /5 (sub r/m8, i8)
            this.emitRegisterMemoryAccess(cast(Register)5, destination);
            this.emitImmediate(cast(byte)immediate);
        }
        else
            assert(false);
    }

    void sub(Register destination, byte immediate)
    {
        if (destination == Register.EAX)
        {
            this.emit(0x2C);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x80);
            // Write 5 to select 0x80 /5 (sub r/m8, i8)
            this.emit(ModRM(destination, cast(Register)5));
            this.emitImmediate(immediate);
        }
    }

    void sub(Register destination, uint immediate)
    {
        if (destination == Register.EAX)
        {
            this.emit(0x2D);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x81);
            // Write 5 to select 0x81 /5 (sub r/m32, i32)
            this.emit(ModRM(destination, cast(Register)5));
            this.emitImmediate(immediate);
        }
    }

    void inc(Register destination)
    {
        // inc eax -> edi
        this.emit(0x40 + cast(ubyte)destination);
    }

    void inc(MemoryAccess destination)
    {
        if (destination.type == OperandType.Byte)
            this.emit(0xFE);
        else
            this.emit(0xFF);

        this.emitRegisterMemoryAccess(cast(Register)0, destination);
    }

    void dec(Register destination)
    {
        // dec eax -> edi
        this.emit(0x48 + cast(ubyte)destination);
    }

    void dec(MemoryAccess destination)
    {
        if (destination.type == OperandType.Byte)
            this.emit(0xFE);
        else
            this.emit(0xFF);

        this.emitRegisterMemoryAccess(cast(Register)1, destination);
    }

    void xor(Register destination, Register source)
    {
        this.emit(0x31);
        this.emit(ModRM(destination, source));
    }

    // Memory
    void push(Register register)
    {
        // push eax -> edi
        this.emit(0x50 + cast(ubyte)register);
    }

    void pop(Register register)
    {
        // pop eax -> edi
        this.emit(0x58 + cast(ubyte)register);
    }

    void mov(Register destination, Register source)
    {
        // mov reg, reg
        this.emit(0x8B);
        this.emit(ModRM(source, destination));
    }

    void mov(MemoryAccess destination, Register source)
    {
        // mov [reg+disp], reg
        this.emit(0x89);
        this.emitRegisterMemoryAccess(source, destination);
    }

    void mov(Register destination, MemoryAccess source)
    {
        if (source.type == OperandType.Byte)
        {
            // mov reg8, byte ptr [reg+disp]
            this.emit(0x8A);
            this.emitRegisterMemoryAccess(destination, source);
        }
        else
        {
            // mov reg, dword ptr [reg+disp]
            this.emit(0x8B);
            this.emitRegisterMemoryAccess(destination, source);            
        }
    }

    void mov(Register destination, uint immediate)
    {
        // mov reg, imm32
        this.emit(0xB8 + cast(ubyte)destination);
        this.emitImmediate(immediate);
    }

    void mov(MemoryAccess destination, byte immediate)
    {
        if (destination.type != OperandType.Byte)
            assert(false);

        this.emit(0xC6);
        // Write 0 to select 0xC6 /0 (mov r/m8, i8)
        this.emitRegisterMemoryAccess(cast(Register)0, destination);
        this.emitImmediate(cast(byte)immediate);
    }

    void mov(MemoryAccess destination, uint immediate)
    {
        if (destination.type != OperandType.DWord)
            assert(false);

        this.emit(0xC7);
        // Write 0 to select 0xC7 /0 (mov r/m32, i32)
        this.emitRegisterMemoryAccess(cast(Register)0, destination);
        this.emitImmediate(immediate);
    }

    void cmp(Register source, ubyte immediate)
    {
        if (source == Register.EAX)
        {
            this.emit(0x3C);
            this.emit(immediate);
        }
    }

    void cmp(Register source, uint immediate)
    {
        if (source == Register.EAX)
        {
            this.emit(0x3D);
            this.emitImmediate(immediate);
        }
        else
        {
            this.emit(0x81);
            // Write 7 to select 0x81 /7 (cmp r/m32, i32)
            this.emit(ModRM(source, cast(Register)7));
            this.emitImmediate(immediate);
        }
    }

    void cmp(MemoryAccess destination, byte immediate)
    {
        if (destination.type == OperandType.Byte)
        {
            this.emit(0x80);
            // Write 7 to select 0x80 /7 (cmp r/m8, i8)
            this.emitRegisterMemoryAccess(cast(Register)7, destination);
            this.emitImmediate(cast(byte)immediate);
        }
        else
            assert(false);
    }

    // Control flow
    void jmp(string name)
    {
        this.emit(0xE9);
        this.emitLabelRelocation(name);
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
    MemoryAccess bytePtr(Args...)(Args args)
    {
        return MemoryAccess(OperandType.Byte, args);
    }

    MemoryAccess dwordPtr(Args...)(Args args)
    {
        return MemoryAccess(OperandType.DWord, args);
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
            foreach (const relocation; block.labelRelocations_)
            {
                this.labelRelocations_ ~= 
                    LabelRelocation(relocation.location + baseAddress, relocation.label);
            }

            // Copy the relocations to the assembly, offseting them as we go along
            foreach (const relocation; block.genericRelocations_)
            {
                this.genericRelocations_ ~= 
                    GenericRelocation(relocation.location + baseAddress, relocation.destination);
            }

            // Update the new base address
            baseAddress += block.buffer_.length;
        }

        // Do relocations
        foreach (const relocation; this.labelRelocations_)
        {
            auto location = relocation.location + 3;
            int offset = cast(int)(this.labels_[relocation.label] - location);
            *cast(int*)&this.buffer_[relocation.location] = offset;
        }

        foreach (const relocation; this.genericRelocations_)
        {
            auto location = relocation.location + this.buffer_.ptr + 4;
            int offset = cast(int)(relocation.destination - location);
            *cast(int*)&this.buffer_[relocation.location] = offset;
        }

        // Add execution privileges to the memory
        version (Windows)
        {
            import std.c.windows.windows;

            DWORD old;
            VirtualProtect(this.buffer_.ptr, this.buffer_.length, 
                           PAGE_EXECUTE_READWRITE, &old);
        }
        else
        {
            import core.sys.posix.sys.mman;
        
            mprotect(this.buffer_.ptr, this.buffer_.length, PROT_READ|PROT_WRITE|PROT_EXEC);
         }
    }

    void dump()
    {
        this.buffer_.map!(a => "%.2X".format(a)).join(" ").writeln();
    }

    @property const(ubyte[]) buffer()
    {
        return this.buffer_;
    }

    T call(T = void, Args...)(Args args)
    {
        extern (C) T function(Args) fn;
        fn = cast(typeof(fn))this.buffer_.ptr;        
        return fn(args);
    }

    void opCall(Args...)(Args args)
    {
        this.call(args);
    }

private:
    Block[] blocks_;
    ubyte[] buffer_;
    size_t[string] labels_;
    LabelRelocation[] labelRelocations_;
    GenericRelocation[] genericRelocations_;
}

unittest
{
    writeln("Test: basic functionality");
    Block preludeBlock, bodyBlock, endBlock;

    static char[] testBuffer;
    static void putchar_test(int c)
    {
        testBuffer ~= c;
    }

    with (preludeBlock) with (Register)
    {
        push(EBP);
        mov(EBP, ESP);       
    }
    
    with (bodyBlock) with (Register)
    {
        xor(EAX, EAX);

        label("LOOP");
        mov(ECX, EAX);
        add(ECX, 65);
        push(EAX);

        // Call putchar, and clean up stack
        mov(EAX, ECX);
        call(&putchar_test);

        pop(EAX);
        inc(EAX);

        cmp(EAX, 26);
        jne("LOOP");
    }

    with (endBlock) with (Register)
    {
        pop(EBP);
        ret;
    }

    auto assembly = Assembly(preludeBlock, bodyBlock, endBlock);
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

    with (block) with (Register)
    {
        push(EBP);
        mov(EBP, ESP);
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

    with (block) with (Register)
    {
        push(EBP);
        mov(EBP, ESP);

        // Load array into EDX
        mov(EDX, dwordPtr(EBP, 8));
        // array[0] += 5
        add(bytePtr(EDX), 5);
        // Move to array[1]
        inc(EDX);
        // array[1] += 10
        add(bytePtr(EDX), 10);
        // Move to array[2]
        inc(EDX);
        // array[2] -= 10
        sub(bytePtr(EDX), 10);

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