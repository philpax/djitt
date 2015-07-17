import std.stdio;
import std.typecons;
import std.bitmanip;
import std.algorithm;
import std.string;

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

struct CodeBlock
{
    void finalize()
    {
        foreach (const relocation; this.labelRelocations_)
        {
            int offset = this.labels_[relocation.label] - relocation.location;
            assert(offset >= byte.min && offset <= byte.max);
            this.buffer_[relocation.location] = cast(ubyte)offset;
        }

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

    void emit(int b)
    {
        this.buffer_ ~= cast(ubyte)b;
    }

    void emitImmediate(T)(T val)
    {
        foreach (i; 0 .. T.sizeof)
            this.buffer_ ~= (cast(ubyte*)&val)[i];
    }

    version (X86_64)
    {
        void emitRexW()
        {
            this.emit(0x48);
        }
    }

    // Arithmetic
    void add(Register destination, Register source)
    {
        this.emit(0x01);
        this.emit(ModRM(destination, source));
    }

    void inc(Register destination)
    {
        version (X86_64)
        {
            this.emitRexW();
            // inc reg
            this.emit(0xFF);
            this.emit(ModRM(destination, Register.EAX));
        }
        else
        {
            // inc eax -> edi
            this.emit(0x40 + cast(ubyte)destination);
        }
    }

    void dec(Register destination)
    {
        // dec eax -> edi
        this.emit(0x48 + cast(ubyte)destination);
    }

    void xor(Register destination, Register source)
    {
        version (X86_64) this.emitRexW();
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
        version (X86_64) this.emitRexW();
        this.emit(0x8B);
        this.emit(ModRM(destination, source));
    }

    void mov(Register destination, uint immediate)
    {
        // mov reg, imm32
        this.emit(0xB8 + cast(ubyte)destination);
        this.emitImmediate(immediate);
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
        this.emit(0x00);
        this.labelRelocations_ ~= LabelRelocation(this.buffer_.length - 1, name);
    }

    void jne(string name)
    {
        this.emit(0x75);
        this.emit(0x00);
        this.labelRelocations_ ~= LabelRelocation(this.buffer_.length - 1, name);
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

    T call(T)()
    {
        extern (C) T function() fn;
        fn = cast(typeof(fn))this.buffer_.ptr;        
        return fn();
    }

private:
    struct LabelRelocation
    {
        size_t location;
        string label;
    }

    ubyte[] buffer_;
    LabelRelocation[] labelRelocations_;
    size_t[string] labels_;
}

void main()
{
    CodeBlock block;
    
    with (block)
    {
        push(Register.EBP);
        mov(Register.ESP, Register.EBP);
        xor(Register.EAX, Register.EAX);
        label("LOOP");
        inc(Register.EAX);
        cmp(Register.EAX, 4);
        jne("LOOP");
        pop(Register.EBP);
        ret();
    }

    block.finalize();
    block.dump();

    writeln(block.call!int());
}
