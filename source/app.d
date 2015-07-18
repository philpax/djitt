import std.stdio;
import std.typecons;
import std.bitmanip;
import std.algorithm;
import std.string;
import std.array;

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

struct LabelRelocation
{
    size_t location;
    string label;
}

bool fitsIn(T, Y)(Y value)
{
    return value >= T.min && value <= T.max;
}

struct BasicBlock
{
    void emit(int b)
    {
        this.buffer_ ~= cast(ubyte)b;
    }

    void emitImmediate(T)(T val)
    {
        foreach (i; 0 .. T.sizeof)
            this.buffer_ ~= (cast(ubyte*)&val)[i];
    }

    void emitRelocation(string name)
    {
        this.emit(0x00);
        this.labelRelocations_ ~= LabelRelocation(this.buffer_.length - 1, name);        
    }

    // Arithmetic
    void add(Register destination, Register source)
    {
        this.emit(0x01);
        this.emit(ModRM(destination, source));
    }

    void inc(Register destination)
    {
        // inc eax -> edi
        this.emit(0x40 + cast(ubyte)destination);
    }

    void dec(Register destination)
    {
        // dec eax -> edi
        this.emit(0x48 + cast(ubyte)destination);
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
        this.emit(ModRM(destination, source));
    }

    void mov(Register destination, uint immediate)
    {
        // mov reg, imm32
        this.emit(0xB8 + cast(ubyte)destination);
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
            assert(false);        
    }

    void jmp(string name)
    {
        this.emit(0xEB);
        this.emitRelocation(name);
    }

    void je(string name)
    {
        this.emit(0x74);
        this.emitRelocation(name);
    }

    void jne(string name)
    {
        this.emit(0x75);
        this.emitRelocation(name);
    }

    void label(string name)
    {
        this.labels_[name] = this.buffer_.length - 1;
    }

    // Control flow
    void ret()
    {
        this.emit(0xC3);
    }

    void dump()
    {
        this.buffer_.map!(a => "%.2X".format(a)).join(" ").writeln();
    }

private:
    ubyte[] buffer_;
    LabelRelocation[] labelRelocations_;
    size_t[string] labels_;
}

struct Assembly
{
    this(BasicBlock[] blocks...)
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

            // Update the new base address
            baseAddress += block.buffer_.length;
        }

        // Do relocations
        foreach (const relocation; this.labelRelocations_)
        {
            int offset = cast(int)(this.labels_[relocation.label] - relocation.location);
            assert(offset.fitsIn!byte());
            this.buffer_[relocation.location] = cast(ubyte)offset;
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

    T call(T)()
    {
        extern (C) T function() fn;
        fn = cast(typeof(fn))this.buffer_.ptr;        
        return fn();
    }

private:
    BasicBlock[] blocks_;
    ubyte[] buffer_;
    size_t[string] labels_;
    LabelRelocation[] labelRelocations_;
}

void main()
{
    BasicBlock preludeBlock, bodyBlock, endBlock;

    with (preludeBlock)
    {
        push(Register.EBP);
        mov(Register.ESP, Register.EBP);        
    }
    
    with (bodyBlock)
    {
        xor(Register.EAX, Register.EAX);
        label("LOOP");
        inc(Register.EAX);
        cmp(Register.EAX, 2);
        je("EXIT");
        cmp(Register.EAX, 4);
        jne("LOOP");
    }

    with (endBlock)
    {
        label("EXIT");
        pop(Register.EBP);
        ret();
    }

    auto assembly = Assembly(preludeBlock, bodyBlock, endBlock);
    assembly.finalize();
    assembly.dump();

    writeln(assembly.call!int());
}
