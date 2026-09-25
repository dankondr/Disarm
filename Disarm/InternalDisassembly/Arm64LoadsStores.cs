namespace Disarm.InternalDisassembly;

internal static class Arm64LoadsStores
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op0 = instruction >> 28; //Bits 28-31
        var op1 = (instruction >> 26) & 1; //Bit 26
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; //Bits 10-11

        //As can perhaps be imagined, this is by far the most deeply-nested tree of instructions
        //At this level, despite having 5 separate operands to differentiate which path we take, most of these paths are defined by masks, not by values.
        //Unfortunately, this makes the code a bit ugly.

        //They are, at least, *somewhat* grouped by category using op0
        if ((op0 & 0b1011) == 0 && op1 == 1)
            //Mostly undefined instructions, but a couple of them are defined
            return DisassembleAdvancedLoadStore(instruction);

        if (op0 == 0b1101 && op1 == 0 && op2 >> 1 == 1 && op3 >> 5 == 1)
            //Literally the only concretely defined value for op0, but it still needs others to match conditions - load/store memory tags
            return DisassembleLoadStoreMemoryTags(instruction);

        //Five more categories for op0

        if ((op0 & 0b1011) == 0b1000)
        {
            //Load/store exclusive pair, or undefined
            if (op1 == 0 && op2 == 0 && op3.TestBit(5))
                return LoadStoreExclusivePair(instruction);

            if (op1 == 1)
                throw new Arm64UndefinedInstructionException($"Load/store: Undefined instruction - op0={op0} and op1={op1}");
            
            //Drop to below
        }

        //The last 4 categories look only at the last 2 bits of op0, so we can switch now
        op0 &= 0b11;

        //Ok i lied half of these are barely grouped at all in any way that makes sense to me 
        return op0 switch
        {
            0b00 => DisassembleLoadStoreExclusiveRegOrderedOrCompareSwap(instruction), //load/store exclusive reg, load/store ordered, or compare + swap 
            0b01 => DisassembleLdAprRegisterLiteralOrMemoryCopySet(instruction), //ldapr/stlr unscaled immediate, load register literal, or memory copy/set
            0b10 => DisassembleLoadStorePairs(instruction), //actual group! load/store pairs
            0b11 => DisassembleLoadStoreRegisterOrAtomic(instruction), //various kinds of load/store register, or atomic memory operations
            _ => throw new("Loads/stores: Impossible op0 value")
        };
    }

    private static Arm64Instruction DisassembleAdvancedLoadStore(uint instruction)
    {
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21

        if (op2 == 0b00 && op3 == 0)
            return Arm64Simd.LoadStoreMultipleStructures(instruction);

        if (op2 == 0b01 && !op3.TestBit(5))
            return Arm64Simd.LoadStoreMultipleStructuresPostIndexed(instruction);

        if (op2 == 0b10 && (op3 & 0b1_1111) == 0)
            return Arm64Simd.LoadStoreSingleStructure(instruction);

        if (op2 == 0b11)
            return Arm64Simd.LoadStoreSingleStructurePostIndexed(instruction);

        throw new Arm64UndefinedInstructionException($"Advanced load/store: Congrats, you hit the minefield of undefined instructions. op2: {op2}, op3: {op3}");
    }

    private static Arm64Instruction DisassembleLoadStoreMemoryTags(uint instruction)
    {
        var opc = (instruction >> 22) & 0b11; // Bits 22-23
        var imm9 = (long) (instruction >> 12) & 0b1_1111_1111; // Bits 12-20
        var op2 = (instruction >> 10) & 0b11; // Bits 10-11
        var rn = (int)(instruction >> 5) & 0b1_1111; // Bits 5-9
        var rt = (int)instruction & 0b1_1111; // Bits 0-5

        imm9 = Arm64CommonUtils.SignExtend(imm9, 9, 64);
        var offset = imm9 << Arm64CommonUtils.LOG2_TAG_GRANULE;
        
        return opc switch
        {
            0b00 when offset != 0 => new()
            {
                Mnemonic = Arm64Mnemonic.STG,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b00 when offset == 0 => new()
            {
                Mnemonic = Arm64Mnemonic.STZGM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            0b01 when op2 == 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.LDG,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            0b01 when op2 != 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.STZG,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b10 when offset != 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.ST2G,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b10 when offset == 0 && op2 == 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.STGM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            0b11 when offset != 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.STZ2G,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b11 when offset == 0 && op2 == 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.LDGM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            _ => throw new Arm64UndefinedInstructionException("Unallocated")
        };
    }

    private static Arm64Instruction DisassembleLoadStoreExclusiveRegOrderedOrCompareSwap(uint instruction)
    {
        //Load/store exclusive register, load/store ordered, or compare + swap
        var op0 = (instruction >> 28) & 0b1111; //Bits 28-31
        var op1 = instruction.TestBit(26); //Bit 26
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; // Bits 10-11
        
        if(op1)
            throw new Arm64UndefinedInstructionException("Load/store (exclusive register|ordered)|compare/swap: op1 set");

        //op3 top bit distinguishes the exclusive/ordered forms from the compare/swap ones
        return op2 switch
        {
            0b00 when !op3.TestBit(5) => LoadStoreExclusive(instruction),
            0b00 => CompareAndSwap(instruction), //compare and swap pair
            0b01 when !op3.TestBit(5) => LoadStoreOrdered(instruction),
            0b01 => CompareAndSwap(instruction),
            _ => throw new Arm64UndefinedInstructionException($"Load/store (exclusive register|ordered)|compare/swap: op0 {op0}, op1 {op1}, op2 {op2}, op3 {op3}, op4 {op4}")
        };
    }

    private static Arm64Instruction LoadStoreExclusive(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isLoad = instruction.TestBit(22);
        var rs = (int)(instruction >> 16) & 0b1_1111; //Bits 16-20
        var o0 = instruction.TestBit(15);
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4

        var mnemonic = size switch
        {
            0b00 when isLoad => o0 ? Arm64Mnemonic.LDAXRB : Arm64Mnemonic.LDXRB,
            0b00 => o0 ? Arm64Mnemonic.STLXRB : Arm64Mnemonic.STXRB,
            0b01 when isLoad => o0 ? Arm64Mnemonic.LDAXRH : Arm64Mnemonic.LDXRH,
            0b01 => o0 ? Arm64Mnemonic.STLXRH : Arm64Mnemonic.STXRH,
            _ when isLoad => o0 ? Arm64Mnemonic.LDAXR : Arm64Mnemonic.LDXR,
            _ => o0 ? Arm64Mnemonic.STLXR : Arm64Mnemonic.STXR,
        };

        var dataBaseReg = size == 0b11 ? Arm64Register.X0 : Arm64Register.W0;

        if (isLoad)
            return new()
            {
                Mnemonic = mnemonic,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = dataBaseReg + rt,
                MemBase = Arm64Register.X0 + rn,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            };

        //stores get a status register, which is always a w reg
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Memory,
            Op0Reg = Arm64Register.W0 + rs,
            Op1Reg = dataBaseReg + rt,
            MemBase = Arm64Register.X0 + rn,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }
    
    private static Arm64Instruction CompareAndSwap(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31: 00 = B, 01 = H, 10 = 32-bit, 11 = 64-bit
        var isCasp = !instruction.TestBit(23); //bit 23 clear => CASP, which operates on a register pair
        var acquire = instruction.TestBit(22); //a
        var release = instruction.TestBit(15); //l
        var rs = (int)(instruction >> 16) & 0b1_1111; //Bits 16-20: expected (old) value
        var rt2 = (int)(instruction >> 10) & 0b1_1111; //Bits 10-14: must be 0b11111
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rt = (int)instruction & 0b1_1111; //Bits 0-4: new value

        if (rt2 != 0b1_1111)
            throw new Arm64UndefinedInstructionException("Compare and swap: bits 10-14 must be all ones");

        if (isCasp && size > 1)
            throw new Arm64UndefinedInstructionException("Compare and swap pair: size must be 0b00 or 0b01");

        if (isCasp)
        {
            //CASP: compares and swaps the register pair <Rs,Rs+1> against the pair <Rt,Rt+1>
            //size 0 => two 32-bit registers, size 1 => two 64-bit registers
            var dataBase = size == 0b01 ? Arm64Register.X0 : Arm64Register.W0;
            var mnemonic = (acquire, release) switch
            {
                (false, false) => Arm64Mnemonic.CASP,
                (false, true) => Arm64Mnemonic.CASPL,
                (true, false) => Arm64Mnemonic.CASPA,
                (true, true) => Arm64Mnemonic.CASPAL,
            };
            return new()
            {
                Mnemonic = mnemonic,
                MnemonicCategory = Arm64MnemonicCategory.Comparison,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Register,
                Op3Kind = Arm64OperandKind.Register,
                Op4Kind = Arm64OperandKind.Memory,
                Op0Reg = dataBase + rs,
                Op1Reg = dataBase + (rs + 1) % 32,
                Op2Reg = dataBase + rt,
                Op3Reg = dataBase + (rt + 1) % 32,
                MemBase = Arm64Register.X0 + rn,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
            };
        }

        //CAS: single register compare-and-swap
        var dataBaseReg = size == 0b11 ? Arm64Register.X0 : Arm64Register.W0;
        var casMnemonic = (size, acquire, release) switch
        {
            (0b00, false, false) => Arm64Mnemonic.CASB,
            (0b00, false, true) => Arm64Mnemonic.CASLB,
            (0b00, true, false) => Arm64Mnemonic.CASAB,
            (0b00, true, true) => Arm64Mnemonic.CASALB,
            (0b01, false, false) => Arm64Mnemonic.CASH,
            (0b01, false, true) => Arm64Mnemonic.CASLH,
            (0b01, true, false) => Arm64Mnemonic.CASAH,
            (0b01, true, true) => Arm64Mnemonic.CASALH,
            (0b10, false, false) => Arm64Mnemonic.CAS,
            (0b10, false, true) => Arm64Mnemonic.CASL,
            (0b10, true, false) => Arm64Mnemonic.CASA,
            (0b10, true, true) => Arm64Mnemonic.CASAL,
            (0b11, false, false) => Arm64Mnemonic.CAS,
            (0b11, false, true) => Arm64Mnemonic.CASL,
            (0b11, true, false) => Arm64Mnemonic.CASA,
            (0b11, true, true) => Arm64Mnemonic.CASAL,
            _ => throw new("Impossible size")
        };
        return new()
        {
            Mnemonic = casMnemonic,
            MnemonicCategory = Arm64MnemonicCategory.Comparison,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Memory,
            Op0Reg = dataBaseReg + rs,
            Op1Reg = dataBaseReg + rt,
            MemBase = Arm64Register.X0 + rn,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
        };
    }
    
    private static Arm64Instruction LoadStoreOrdered(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; // 00 = B, 01 = H, 10 = 32-bit variant, 11 = 64-bit variant
        var L = instruction.TestBit(22); //1 = Load, 0 = Store
        var o0 = instruction.TestBit(15); //0 = FEAT_LOR instruction group

        var mnemonic = size switch
        {
            0b00 when L && !o0 => Arm64Mnemonic.LDLARB,
            0b00 when L => Arm64Mnemonic.LDARB,
            0b00 when !L && !o0 => Arm64Mnemonic.STLLRB,
            0b00 when !L => Arm64Mnemonic.STLRB,

            0b01 when L && !o0 => Arm64Mnemonic.LDLARH,
            0b01 when L => Arm64Mnemonic.LDARH,
            0b01 when !L && !o0 => Arm64Mnemonic.STLLRH,
            0b01 when !L => Arm64Mnemonic.STLRH,

            0b10 when L && !o0 => Arm64Mnemonic.LDLAR,
            0b10 when L => Arm64Mnemonic.LDAR,
            0b10 when !L && !o0 => Arm64Mnemonic.STLLR,
            0b10 when !L => Arm64Mnemonic.STLR,

            0b11 when L && !o0 => Arm64Mnemonic.LDLAR,
            0b11 when L => Arm64Mnemonic.LDAR,
            0b11 when !L && !o0 => Arm64Mnemonic.STLLR,
            0b11 when !L => Arm64Mnemonic.STLR,

            _ => throw new Arm64UndefinedInstructionException("LoadStoreOrdered: Impossible combination")
        };

        var Rs = instruction >> 16 & 0b1_1111; //doesn't appear to actually be used
        var Rt2  = instruction >> 10 & 0b1_1111; //doesn't appear to actually be used
        var Rn = instruction >> 5 & 0b1_1111;
        var Rt = instruction & 0b1_1111;

        var baseTReg = size switch
        {
            0b00 or 0b01 or 0b10 => Arm64Register.W0,
            0b11 => Arm64Register.X0,
            _ => throw new Arm64UndefinedInstructionException("LoadStoreOrdered: Impossible combination")
        };
        
        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            Op0Reg = baseTReg + (int)Rt,
            MemBase = Arm64Register.X0 + (int)Rn,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
        };
    }

    private static Arm64Instruction DisassembleLdAprRegisterLiteralOrMemoryCopySet(uint instruction)
    {
        //LDAPR/STLR, load/store register literal, memory copy, or memory set
        var op1 = instruction.TestBit(26); //Bit 26
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; //Bits 10-11

        if (!op2.TestBit(1))
            return LoadRegisterLiteral(instruction);
        
        if(op3.TestBit(5))
            throw new Arm64UndefinedInstructionException("LdAprRegisterLiteralOrMemoryCopySet: op3 hi bit set");

        return op4.TestBit(0)
            ? MemoryCopyOrSet(instruction)
            : LdarpOrStlr(instruction);
    }
    
    private static Arm64Instruction LoadRegisterLiteral(uint instruction)
    {
        var opc = (instruction >> 30) & 0b11; // Bits 30-31
        var v = instruction.TestBit(26);
        var imm19 = (instruction >> 5) & 0b111_1111_1111_1111_1111; // Bits 5-23
        imm19 <<= 2; //4-byte aligned
        var label = Arm64CommonUtils.SignExtend(imm19, 21, 64); //21 is 19 + 2 for the left shift
        var rt = (int)instruction & 0b1_1111;
        
        return opc switch
        {
            (0b00 or 0b01) when !v => new()
            {
                Mnemonic = Arm64Mnemonic.LDR,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt,
                Op1Imm = label
            },
            0b10 when !v =>  new()
            {
                Mnemonic = Arm64Mnemonic.LDRSW,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Reg = Arm64Register.X0 + rt,
                Op1Imm = label
            },
            0b11 when !v =>  new()
            {
                Mnemonic = Arm64Mnemonic.PRFM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Immediate,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Imm = rt, //TODO Prefetch isn't just a raw imm, it's a combination of well-defined type | cache level | cache policy
                Op1Imm = label
            },
            (0b00 or 0b01 or 0b10) when v => new()
            {
                Mnemonic = Arm64Mnemonic.LDR,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Reg = (opc == 0b00 ? Arm64Register.S0 : opc == 0b01 ? Arm64Register.D0 : Arm64Register.V0) + rt,
                Op1Imm = label
            },
            _ => throw new Arm64UndefinedInstructionException("Unallocated")
        };
    }
    
    private static Arm64Instruction MemoryCopyOrSet(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Move, 
        };
    }
    
    private static Arm64Instruction LdarpOrStlr(uint instruction)
    {
        // FEAT_LRCPC2
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
        };
    }

    private static Arm64Instruction DisassembleLoadStorePairs(uint instruction)
    {
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24

        return op2 switch
        {
            0b00 => LoadStoreNoAllocatePairs(instruction), //load/store no-allocate pairs
            0b01 => LoadStoreRegisterPair(instruction, Arm64MemoryIndexMode.PostIndex), //load/store register pair (post-indexed)
            0b10 => LoadStoreRegisterPair(instruction, Arm64MemoryIndexMode.Offset), //load/store register pair (offset)
            0b11 => LoadStoreRegisterPair(instruction, Arm64MemoryIndexMode.PreIndex), //load/store register pair (pre-indexed)
            _ => throw new("Loads/store pairs: Impossible op2 value")
        };
    }

    //The 'xx11' category of loads/stores
    private static Arm64Instruction DisassembleLoadStoreRegisterOrAtomic(uint instruction)
    {
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; //Bits 10-11

        //Bottom bit of op2 is irrelevant
        op2 >>= 1;

        if (op2 == 1)
            //Load/store reg unsigned immediate
            return LoadStoreRegFromImmUnsigned(instruction);

        //Check top bit of op3
        if (op3 >> 5 == 1)
            //Atomic, or load/store reg with non-immediate, depending on op1
            return op4 switch
            {
                0b00 => AtomicMemoryOperation(instruction), //Atomic
                0b10 => LoadStoreRegisterFromRegisterOffset(instruction), //Load/store (reg), (reg + x)
                _ => LoadStoreRegisterFromPac(instruction), //Load store (reg), (pac)
            };

        //Some kind of load/store reg with an immediate
        return op4 switch
        {
            0b00 => LoadStoreRegisterFromImmUnscaled(instruction), //Load/store (reg), (unscaled immediate)
            0b01 => LoadStoreRegisterFromImm(instruction, Arm64MemoryIndexMode.PostIndex), //Load/store (reg), (post-indexed immediate)
            0b10 => LoadStoreRegisterUnprivileged(instruction), //Load/store (reg), (unprivileged)
            0b11 => LoadStoreRegisterFromImm(instruction, Arm64MemoryIndexMode.PreIndex), //Load/Store (reg), (pre-indexed immediate)
            _ => throw new("Impossible op4"),
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromImm(uint instruction, Arm64MemoryIndexMode memoryIndexMode)
    {
        // Load/store immediate pre-indexed

        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26); //Bit 26
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var imm9 = (instruction >> 12) & 0b1_1111_1111; //Bits 12-20
        var rn = (int)(instruction >> 5) & 0b11111; //Bits 5-9
        var rt = (int)(instruction & 0b11111); //Bits 0-4

        if (size is 0b10 or 0b11)
        {
            var invalid = isVector ? opc is 0b10 or 0b11 : opc is 0b11;
            
            if (invalid)
                throw new Arm64UndefinedInstructionException($"Load/store immediate pre-indexed: Invalid size/opc combination. size: {size}, opc: {opc}");
        }
        
        //Note to self - this logic is copied from further down but has had some minor adjustments made, it may still be incorrect in places
        //so if something seems wrong, it probably is!
        var mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.STRB,
                0b01 when !isVector => Arm64Mnemonic.STRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.STR,
                _ when isVector => Arm64Mnemonic.STR,
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRB,
                0b01 when !isVector => Arm64Mnemonic.LDRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.LDR,
                _ when isVector => Arm64Mnemonic.LDR,
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //64-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //64-bit variant
                0b10 when !isVector => Arm64Mnemonic.LDRSW,
                0b00 when isVector => Arm64Mnemonic.STR, //128-bit store
                //PRFM has no pre/post-indexed forms; size 0b11 with opc 0b10 is reserved here
                _ => throw new Arm64UndefinedInstructionException($"Load/store register from immediate: invalid size/opc combination. size: {size}, opc: {opc}")
            },
            0b11 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //32-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //32-bit variant
                0b00 when isVector => Arm64Mnemonic.LDR, //128-bit load
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };

        var baseReg = mnemonic switch
        {
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector && opc is 0 or 1 => size switch
            {
                0 => Arm64Register.B0,
                1 => Arm64Register.H0,
                2 => Arm64Register.S0,
                3 => Arm64Register.D0,
                _ => throw new("Impossible size")
            },
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector => Arm64Register.V0, //128-bit vector
            Arm64Mnemonic.STRB or Arm64Mnemonic.LDRB or Arm64Mnemonic.STRH or Arm64Mnemonic.LDRH => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR => Arm64Register.X0,
            Arm64Mnemonic.LDRSB or Arm64Mnemonic.LDRSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDRSB or Arm64Mnemonic.LDRSH => Arm64Register.W0,
            Arm64Mnemonic.LDRSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };
        
        var regT = baseReg + rt;
        var regN = Arm64Register.X0 + rn;
        
        var offset = Arm64CommonUtils.SignExtend(imm9, 9, 64);

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            MemIndexMode = memoryIndexMode,
            Op0Reg = regT,
            MemBase = regN,
            MemOffset = offset,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreNoAllocatePairs(uint instruction)
    {
        var opc = (instruction >> 30) & 0b11; // Bits 30-31
        var v = instruction.TestBit(26);
        var l = instruction.TestBit(22);

        var imm7 = (instruction >> 15) & 0b111_1111; // Bits - 15-21
        var rt2 = (int)(instruction >> 10) & 0b1_1111; // Bits - 10-14
        var rn = (int)(instruction >> 5) & 0b1_1111; // Bits - 5-9
        var rt = (int)instruction & 0b1_1111; // Bits - 0-14

        var offset = Arm64CommonUtils.SignExtend(imm7, 7, 64) << (v ? 2 + (int)opc : opc == 0b00 ? 2 : 3);
        
        return opc switch
        {
            (0b00 or 0b10) when !v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt,
                Op1Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt2
            },
            (0b00 or 0b10) when !v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt,
                Op1Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt2
            },
            0b00 when v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.S0 + rt,
                Op1Reg = Arm64Register.S0 + rt2
            },
            0b01 when v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.D0 + rt,
                Op1Reg = Arm64Register.D0 + rt2
            },
            0b10 when v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.V0 + rt, // aka Q0
                Op1Reg = Arm64Register.V0 + rt2 // aka Q0
            },
            0b00 when v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.S0 + rt,
                Op1Reg = Arm64Register.S0 + rt2
            },
            0b01 when v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.D0 + rt,
                Op1Reg = Arm64Register.D0 + rt2
            },
            0b10 when v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.V0 + rt, // aka Q0
                Op1Reg = Arm64Register.V0 + rt2 // aka Q0
            },
            _ => throw new Arm64UndefinedInstructionException("Unallocated")
        };
    }

    private static Arm64Instruction LoadStoreRegisterPair(uint instruction, Arm64MemoryIndexMode mode)
    {
        //Page C4-559

        var opc = (instruction >> 30) & 0b11; //Bits 30-31
        var imm7 = (instruction >> 15) & 0b111_1111; //Bits 15-21
        var rt2 = (int)(instruction >> 10) & 0b1_1111; //Bits 10-14
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4

        var isVector = instruction.TestBit(26);
        var isLoad = instruction.TestBit(22);

        //opc: 
        //00 - stp/ldp (32-bit + 32-bit fp)
        //01 - stgp, ldpsw, stp/ldp (64-bit fp)
        //10 - stp/ldp (64-bit + 128-bit fp)
        //11 - reserved

        if (opc == 0b11)
            throw new Arm64UndefinedInstructionException("Load/store register pair (pre-indexed): opc == 0b11");

        var mnemonic = isLoad ? Arm64Mnemonic.LDP : Arm64Mnemonic.STP;

        if (opc == 1 && !isVector)
            mnemonic = isLoad ? Arm64Mnemonic.LDPSW : Arm64Mnemonic.STGP; //Store Allocation taG (64-bit) and Pair/LoaD Pair of registers Signed Ward (32-bit) 

        var destBaseReg = opc switch
        {
            0b00 when isVector => Arm64Register.S0, //32-bit vector
            0b00 => Arm64Register.W0, //32-bit
            0b01 when isVector => Arm64Register.D0, //64-bit vector
            0b01 => Arm64Register.X0, //ldpsw and stgp both use x regs
            0b10 when isVector => Arm64Register.V0, //128-bit vector
            0b10 => Arm64Register.X0, //64-bit
            _ => throw new("Impossible opc value")
        };

        //ldpsw loads two 32-bit words, stgp works on 16-byte tag granules, everything else matches register width
        var offsetScaleBytes = opc switch
        {
            0b00 => 4,
            0b01 when mnemonic == Arm64Mnemonic.LDPSW => 4,
            0b01 when mnemonic == Arm64Mnemonic.STGP => 16,
            0b01 => 8,
            0b10 when isVector => 16,
            0b10 => 8,
            _ => throw new("Impossible opc value")
        };

        //The offset must be aligned to the size of the data so is stored in imm7 divided by this factor
        //So we multiply by the size of the data to get the offset
        //It is stored signed.
        var realImm7 = Arm64CommonUtils.CorrectSignBit(imm7, 7);

        var reg1 = destBaseReg + rt;
        var reg2 = destBaseReg + rt2;
        var regN = Arm64Register.X0 + rn;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Memory,
            Op0Reg = reg1,
            Op1Reg = reg2,
            MemBase = regN,
            MemOffset = realImm7 * offsetScaleBytes,
            MemIndexMode = mode,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreRegFromImmUnsigned(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26);
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var imm12 = (instruction >> 10) & 0b1111_1111_1111; //Bits 10-21
        var rn = (int)(instruction >> 5) & 0b11111; //Bits 5-9
        var rt = (int)(instruction & 0b11111); //Bits 0-4
        
        //Zero extend imm12 to 64-bit
        var immediate = (long)imm12;
        immediate <<= (int) size; //Shift left by the size... apparently?

        Arm64Register baseReg;
        Arm64Mnemonic mnemonic;
        
        if (isVector)
        {
            //For once, SIMD/FP is the simple path. It's always LDR or STR, and for all but the 128-bit version, the register depends on size
            //Let's get the 128-bit check out first
            if (opc is 0b10 or 0b11)
            {
                //128-bit. Ensure size is 00
                if (size != 0)
                    throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc 0b10/0b11 unallocated for size > 0");
                
                mnemonic = opc == 0b10 ? Arm64Mnemonic.STR : Arm64Mnemonic.LDR;
                baseReg = Arm64Register.V0; //128-bit variant
                immediate <<= 4; //size is 00 for q regs, the actual scale is 16 bytes
            }
            else
            {
                mnemonic = opc == 0b00 ? Arm64Mnemonic.STR : Arm64Mnemonic.LDR;
                baseReg = size switch
                {
                    0b00 => Arm64Register.B0, //8-bit variant
                    0b01 => Arm64Register.H0, //16-bit variant
                    0b10 => Arm64Register.S0, //32-bit variant
                    0b11 => Arm64Register.D0, //64-bit variant
                    _ => throw new("Impossible size")
                };
            }
            
            return new()
            {
                Mnemonic = mnemonic,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = baseReg + rt,
                MemBase = Arm64Register.X0 + rn,
                MemOffset = immediate,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            };
        }
        
        //Now we have to deal with the non-SIMD/FP case.

        //This is considerably less clean than it perhaps could be because they don't stick to patterns and 
        //the mnemonics are different for different sizes.
        //Example - in general, even opc is a store, odd is a load. But opc == 11 && !v && size = 0 => LDRSB. :(
        mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 => Arm64Mnemonic.STRB,
                0b01 => Arm64Mnemonic.STRH,
                0b10 or 0b11 => Arm64Mnemonic.STR, //32 or 64-bit
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 => Arm64Mnemonic.LDRB,
                0b01 => Arm64Mnemonic.LDRH,
                0b10 or 0b11 => Arm64Mnemonic.LDR, //32 or 64-bit
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                //These all break the rules, they are loads but they are even opc
                0b00 => Arm64Mnemonic.LDRSB, //64-bit variant
                0b01 => Arm64Mnemonic.LDRSH, //64-bit variant
                0b10 => Arm64Mnemonic.LDRSW,
                0b11 => Arm64Mnemonic.PRFM, //prefetch, unsigned scaled immediate
                _ => throw new($"Impossible size: {size}")
            },
            0b11 => size switch
            {
                0b00 => Arm64Mnemonic.LDRSB, //32-bit variant
                0b01 => Arm64Mnemonic.LDRSH, //32-bit variant
                0b10 => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc 0b11 unallocated for size 0b10"),
                0b11 => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc 0b11 unallocated for size 0b11"),
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };

        if (mnemonic == Arm64Mnemonic.PRFM)
        {
            //PRFM has a prefetch operation operand instead of a data register
            return new()
            {
                Mnemonic = Arm64Mnemonic.PRFM,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = rt,
                Op1Kind = Arm64OperandKind.Memory,
                MemBase = Arm64Register.X0 + rn,
                MemOffset = immediate,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            };
        }

        baseReg = mnemonic switch
        {
            Arm64Mnemonic.STRB or Arm64Mnemonic.LDRB or Arm64Mnemonic.STRH or Arm64Mnemonic.LDRH => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR => Arm64Register.X0,
            Arm64Mnemonic.LDRSB or Arm64Mnemonic.LDRSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDRSB or Arm64Mnemonic.LDRSH => Arm64Register.W0,
            Arm64Mnemonic.LDRSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            Op0Reg = baseReg + rt,
            MemBase = Arm64Register.X0 + rn,
            MemOffset = immediate,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction AtomicMemoryOperation(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31: element width B/H/W/X
        var acquire = instruction.TestBit(23); //a bit - not present on the ST* store-alias form
        var release = instruction.TestBit(22); //r bit - LDADDL etc.
        var rs = (int)(instruction >> 16) & 0b1_1111; //Bits 16-20: value register
        var opc = (instruction >> 12) & 0b1111; //Bits 12-15: operation
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rt = (int)instruction & 0b1_1111; //Bits 0-4: destination, or 31 for the store alias

        if (opc >= 0b1001)
            //0b1001-0b1011 are the RCW* pair operations (FEAT_LSE128), everything above is unallocated
            throw new Arm64UndefinedInstructionException($"Atomic memory operation: opc 0b{opc:B} is reserved");

        var dataBase = size == 0b11 ? Arm64Register.X0 : Arm64Register.W0;

        //With rt == 31 and a == 0 the read-back goes to the zero register, so the LD* form
        //becomes a plain ST* store-alias; with a == 1 the LD mnemonic is kept and Rt prints as wzr/xzr.
        //SWP always keeps its mnemonic and the zero-register operand.
        var useStoreAlias = rt == 0b1_1111 && !acquire && opc < 0b1000;

        var mnemonic = (opc, size, release, useStoreAlias) switch
        {
            (0b0000, 0b00, false, false) => Arm64Mnemonic.LDADDB,
            (0b0000, 0b00, false, true) => Arm64Mnemonic.STADDB,
            (0b0000, 0b00, true, false) => Arm64Mnemonic.LDADDLB,
            (0b0000, 0b00, true, true) => Arm64Mnemonic.STADDLB,
            (0b0000, 0b01, false, false) => Arm64Mnemonic.LDADDH,
            (0b0000, 0b01, false, true) => Arm64Mnemonic.STADDH,
            (0b0000, 0b01, true, false) => Arm64Mnemonic.LDADDLH,
            (0b0000, 0b01, true, true) => Arm64Mnemonic.STADDLH,
            (0b0000, >= 0b10, false, false) => Arm64Mnemonic.LDADD,
            (0b0000, >= 0b10, false, true) => Arm64Mnemonic.STADD,
            (0b0000, >= 0b10, true, false) => Arm64Mnemonic.LDADDL,
            (0b0000, >= 0b10, true, true) => Arm64Mnemonic.STADDL,
            (0b0001, 0b00, false, false) => Arm64Mnemonic.LDCLRB,
            (0b0001, 0b00, false, true) => Arm64Mnemonic.STCLRB,
            (0b0001, 0b00, true, false) => Arm64Mnemonic.LDCLRLB,
            (0b0001, 0b00, true, true) => Arm64Mnemonic.STCLRLB,
            (0b0001, 0b01, false, false) => Arm64Mnemonic.LDCLRH,
            (0b0001, 0b01, false, true) => Arm64Mnemonic.STCLRH,
            (0b0001, 0b01, true, false) => Arm64Mnemonic.LDCLRLH,
            (0b0001, 0b01, true, true) => Arm64Mnemonic.STCLRLH,
            (0b0001, >= 0b10, false, false) => Arm64Mnemonic.LDCLR,
            (0b0001, >= 0b10, false, true) => Arm64Mnemonic.STCLR,
            (0b0001, >= 0b10, true, false) => Arm64Mnemonic.LDCLRL,
            (0b0001, >= 0b10, true, true) => Arm64Mnemonic.STCLRL,
            (0b0010, 0b00, false, false) => Arm64Mnemonic.LDEORB,
            (0b0010, 0b00, false, true) => Arm64Mnemonic.STEORB,
            (0b0010, 0b00, true, false) => Arm64Mnemonic.LDEORLB,
            (0b0010, 0b00, true, true) => Arm64Mnemonic.STEORLB,
            (0b0010, 0b01, false, false) => Arm64Mnemonic.LDEORH,
            (0b0010, 0b01, false, true) => Arm64Mnemonic.STEORH,
            (0b0010, 0b01, true, false) => Arm64Mnemonic.LDEORLH,
            (0b0010, 0b01, true, true) => Arm64Mnemonic.STEORLH,
            (0b0010, >= 0b10, false, false) => Arm64Mnemonic.LDEOR,
            (0b0010, >= 0b10, false, true) => Arm64Mnemonic.STEOR,
            (0b0010, >= 0b10, true, false) => Arm64Mnemonic.LDEORL,
            (0b0010, >= 0b10, true, true) => Arm64Mnemonic.STEORL,
            (0b0011, 0b00, false, false) => Arm64Mnemonic.LDSETB,
            (0b0011, 0b00, false, true) => Arm64Mnemonic.STSETB,
            (0b0011, 0b00, true, false) => Arm64Mnemonic.LDSETLB,
            (0b0011, 0b00, true, true) => Arm64Mnemonic.STSETLB,
            (0b0011, 0b01, false, false) => Arm64Mnemonic.LDSETH,
            (0b0011, 0b01, false, true) => Arm64Mnemonic.STSETH,
            (0b0011, 0b01, true, false) => Arm64Mnemonic.LDSETLH,
            (0b0011, 0b01, true, true) => Arm64Mnemonic.STSETLH,
            (0b0011, >= 0b10, false, false) => Arm64Mnemonic.LDSET,
            (0b0011, >= 0b10, false, true) => Arm64Mnemonic.STSET,
            (0b0011, >= 0b10, true, false) => Arm64Mnemonic.LDSETL,
            (0b0011, >= 0b10, true, true) => Arm64Mnemonic.STSETL,
            (0b0100, 0b00, false, false) => Arm64Mnemonic.LDSMAXB,
            (0b0100, 0b00, false, true) => Arm64Mnemonic.STSMAXB,
            (0b0100, 0b00, true, false) => Arm64Mnemonic.LDSMAXLB,
            (0b0100, 0b00, true, true) => Arm64Mnemonic.STSMAXLB,
            (0b0100, 0b01, false, false) => Arm64Mnemonic.LDSMAXH,
            (0b0100, 0b01, false, true) => Arm64Mnemonic.STSMAXH,
            (0b0100, 0b01, true, false) => Arm64Mnemonic.LDSMAXLH,
            (0b0100, 0b01, true, true) => Arm64Mnemonic.STSMAXLH,
            (0b0100, >= 0b10, false, false) => Arm64Mnemonic.LDSMAX,
            (0b0100, >= 0b10, false, true) => Arm64Mnemonic.STSMAX,
            (0b0100, >= 0b10, true, false) => Arm64Mnemonic.LDSMAXL,
            (0b0100, >= 0b10, true, true) => Arm64Mnemonic.STSMAXL,
            (0b0101, 0b00, false, false) => Arm64Mnemonic.LDSMINB,
            (0b0101, 0b00, false, true) => Arm64Mnemonic.STSMINB,
            (0b0101, 0b00, true, false) => Arm64Mnemonic.LDSMINLB,
            (0b0101, 0b00, true, true) => Arm64Mnemonic.STSMINLB,
            (0b0101, 0b01, false, false) => Arm64Mnemonic.LDSMINH,
            (0b0101, 0b01, false, true) => Arm64Mnemonic.STSMINH,
            (0b0101, 0b01, true, false) => Arm64Mnemonic.LDSMINLH,
            (0b0101, 0b01, true, true) => Arm64Mnemonic.STSMINLH,
            (0b0101, >= 0b10, false, false) => Arm64Mnemonic.LDSMIN,
            (0b0101, >= 0b10, false, true) => Arm64Mnemonic.STSMIN,
            (0b0101, >= 0b10, true, false) => Arm64Mnemonic.LDSMINL,
            (0b0101, >= 0b10, true, true) => Arm64Mnemonic.STSMINL,
            (0b0110, 0b00, false, false) => Arm64Mnemonic.LDUMAXB,
            (0b0110, 0b00, false, true) => Arm64Mnemonic.STUMAXB,
            (0b0110, 0b00, true, false) => Arm64Mnemonic.LDUMAXLB,
            (0b0110, 0b00, true, true) => Arm64Mnemonic.STUMAXLB,
            (0b0110, 0b01, false, false) => Arm64Mnemonic.LDUMAXH,
            (0b0110, 0b01, false, true) => Arm64Mnemonic.STUMAXH,
            (0b0110, 0b01, true, false) => Arm64Mnemonic.LDUMAXLH,
            (0b0110, 0b01, true, true) => Arm64Mnemonic.STUMAXLH,
            (0b0110, >= 0b10, false, false) => Arm64Mnemonic.LDUMAX,
            (0b0110, >= 0b10, false, true) => Arm64Mnemonic.STUMAX,
            (0b0110, >= 0b10, true, false) => Arm64Mnemonic.LDUMAXL,
            (0b0110, >= 0b10, true, true) => Arm64Mnemonic.STUMAXL,
            (0b0111, 0b00, false, false) => Arm64Mnemonic.LDUMINB,
            (0b0111, 0b00, false, true) => Arm64Mnemonic.STUMINB,
            (0b0111, 0b00, true, false) => Arm64Mnemonic.LDUMINLB,
            (0b0111, 0b00, true, true) => Arm64Mnemonic.STUMINLB,
            (0b0111, 0b01, false, false) => Arm64Mnemonic.LDUMINH,
            (0b0111, 0b01, false, true) => Arm64Mnemonic.STUMINH,
            (0b0111, 0b01, true, false) => Arm64Mnemonic.LDUMINLH,
            (0b0111, 0b01, true, true) => Arm64Mnemonic.STUMINLH,
            (0b0111, >= 0b10, false, false) => Arm64Mnemonic.LDUMIN,
            (0b0111, >= 0b10, false, true) => Arm64Mnemonic.STUMIN,
            (0b0111, >= 0b10, true, false) => Arm64Mnemonic.LDUMINL,
            (0b0111, >= 0b10, true, true) => Arm64Mnemonic.STUMINL,
            (0b1000, 0b00, false, false) => Arm64Mnemonic.SWPB,
            (0b1000, 0b00, false, true) => Arm64Mnemonic.SWPB, //SWP keeps its mnemonic on the wzr read-back
            (0b1000, 0b00, true, false) => Arm64Mnemonic.SWPLB,
            (0b1000, 0b00, true, true) => Arm64Mnemonic.SWPLB,
            (0b1000, 0b01, false, false) => Arm64Mnemonic.SWPH,
            (0b1000, 0b01, false, true) => Arm64Mnemonic.SWPH,
            (0b1000, 0b01, true, false) => Arm64Mnemonic.SWPLH,
            (0b1000, 0b01, true, true) => Arm64Mnemonic.SWPLH,
            (0b1000, >= 0b10, false, false) => Arm64Mnemonic.SWP,
            (0b1000, >= 0b10, false, true) => Arm64Mnemonic.SWP,
            (0b1000, >= 0b10, true, false) => Arm64Mnemonic.SWPL,
            (0b1000, >= 0b10, true, true) => Arm64Mnemonic.SWPL,
            _ => throw new Arm64UndefinedInstructionException("Atomic memory operation: unallocated operation")
        };

        //the acquire bit prepends an A to the mnemonic where present (e.g. LDADDAB, SWPAL)
        if (acquire)
        {
            mnemonic = mnemonic switch
            {
                Arm64Mnemonic.LDADDB => Arm64Mnemonic.LDADDAB,
                Arm64Mnemonic.LDADDLB => Arm64Mnemonic.LDADDALB,
                Arm64Mnemonic.LDADDH => Arm64Mnemonic.LDADDAH,
                Arm64Mnemonic.LDADDLH => Arm64Mnemonic.LDADDALH,
                Arm64Mnemonic.LDADD => Arm64Mnemonic.LDADDA,
                Arm64Mnemonic.LDADDL => Arm64Mnemonic.LDADDAL,
                Arm64Mnemonic.LDCLRB => Arm64Mnemonic.LDCLRAB,
                Arm64Mnemonic.LDCLRLB => Arm64Mnemonic.LDCLRALB,
                Arm64Mnemonic.LDCLRH => Arm64Mnemonic.LDCLRAH,
                Arm64Mnemonic.LDCLRLH => Arm64Mnemonic.LDCLRALH,
                Arm64Mnemonic.LDCLR => Arm64Mnemonic.LDCLRA,
                Arm64Mnemonic.LDCLRL => Arm64Mnemonic.LDCLRAL,
                Arm64Mnemonic.LDEORB => Arm64Mnemonic.LDEORAB,
                Arm64Mnemonic.LDEORLB => Arm64Mnemonic.LDEORALB,
                Arm64Mnemonic.LDEORH => Arm64Mnemonic.LDEORAH,
                Arm64Mnemonic.LDEORLH => Arm64Mnemonic.LDEORALH,
                Arm64Mnemonic.LDEOR => Arm64Mnemonic.LDEORA,
                Arm64Mnemonic.LDEORL => Arm64Mnemonic.LDEORAL,
                Arm64Mnemonic.LDSETB => Arm64Mnemonic.LDSETAB,
                Arm64Mnemonic.LDSETLB => Arm64Mnemonic.LDSETALB,
                Arm64Mnemonic.LDSETH => Arm64Mnemonic.LDSETAH,
                Arm64Mnemonic.LDSETLH => Arm64Mnemonic.LDSETALH,
                Arm64Mnemonic.LDSET => Arm64Mnemonic.LDSETA,
                Arm64Mnemonic.LDSETL => Arm64Mnemonic.LDSETAL,
                Arm64Mnemonic.LDSMAXB => Arm64Mnemonic.LDSMAXAB,
                Arm64Mnemonic.LDSMAXLB => Arm64Mnemonic.LDSMAXALB,
                Arm64Mnemonic.LDSMAXH => Arm64Mnemonic.LDSMAXAH,
                Arm64Mnemonic.LDSMAXLH => Arm64Mnemonic.LDSMAXALH,
                Arm64Mnemonic.LDSMAX => Arm64Mnemonic.LDSMAXA,
                Arm64Mnemonic.LDSMAXL => Arm64Mnemonic.LDSMAXAL,
                Arm64Mnemonic.LDSMINB => Arm64Mnemonic.LDSMINAB,
                Arm64Mnemonic.LDSMINLB => Arm64Mnemonic.LDSMINALB,
                Arm64Mnemonic.LDSMINH => Arm64Mnemonic.LDSMINAH,
                Arm64Mnemonic.LDSMINLH => Arm64Mnemonic.LDSMINALH,
                Arm64Mnemonic.LDSMIN => Arm64Mnemonic.LDSMINA,
                Arm64Mnemonic.LDSMINL => Arm64Mnemonic.LDSMINAL,
                Arm64Mnemonic.LDUMAXB => Arm64Mnemonic.LDUMAXAB,
                Arm64Mnemonic.LDUMAXLB => Arm64Mnemonic.LDUMAXALB,
                Arm64Mnemonic.LDUMAXH => Arm64Mnemonic.LDUMAXAH,
                Arm64Mnemonic.LDUMAXLH => Arm64Mnemonic.LDUMAXALH,
                Arm64Mnemonic.LDUMAX => Arm64Mnemonic.LDUMAXA,
                Arm64Mnemonic.LDUMAXL => Arm64Mnemonic.LDUMAXAL,
                Arm64Mnemonic.LDUMINB => Arm64Mnemonic.LDUMINAB,
                Arm64Mnemonic.LDUMINLB => Arm64Mnemonic.LDUMINALB,
                Arm64Mnemonic.LDUMINH => Arm64Mnemonic.LDUMINAH,
                Arm64Mnemonic.LDUMINLH => Arm64Mnemonic.LDUMINALH,
                Arm64Mnemonic.LDUMIN => Arm64Mnemonic.LDUMINA,
                Arm64Mnemonic.LDUMINL => Arm64Mnemonic.LDUMINAL,
                Arm64Mnemonic.SWPB => Arm64Mnemonic.SWPAB,
                Arm64Mnemonic.SWPLB => Arm64Mnemonic.SWPALB,
                Arm64Mnemonic.SWPH => Arm64Mnemonic.SWPAH,
                Arm64Mnemonic.SWPLH => Arm64Mnemonic.SWPALH,
                Arm64Mnemonic.SWP => Arm64Mnemonic.SWPA,
                Arm64Mnemonic.SWPL => Arm64Mnemonic.SWPAL,
                _ => mnemonic
            };
        }

        if (useStoreAlias)
        {
            //ST<op><l><size>: single register operand, no read-back
            return new()
            {
                Mnemonic = mnemonic,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = dataBase + rs,
                MemBase = Arm64Register.X0 + rn,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
            };
        }

        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Memory,
            Op0Reg = dataBase + rs,
            Op1Reg = dataBase + rt,
            MemBase = Arm64Register.X0 + rn,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromRegisterOffset(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26);
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var rm = (int)(instruction >> 16) & 0b1_1111; //Bits 16-20
        var option = (instruction >> 13) & 0b111; //Bits 13-15
        var sFlag = instruction.TestBit(12);
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4

        if (!option.TestBit(1))
            throw new Arm64UndefinedInstructionException("Load/store register from register offset: option<1> == 0 is unallocated");

        var mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.STRB,
                0b01 when !isVector => Arm64Mnemonic.STRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.STR,
                _ when isVector => Arm64Mnemonic.STR,
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRB,
                0b01 when !isVector => Arm64Mnemonic.LDRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.LDR,
                _ when isVector => Arm64Mnemonic.LDR,
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //64-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //64-bit variant
                0b10 when !isVector => Arm64Mnemonic.LDRSW,
                0b11 when !isVector => Arm64Mnemonic.PRFM,
                0b00 when isVector => Arm64Mnemonic.STR, 
                _ when isVector => throw new Arm64UndefinedInstructionException("Load/store register from register offset: opc 0b10 unallocated for vectors when size > 0"),
                _ => throw new($"Impossible size: {size}")
            },
            0b11 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //32-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //32-bit variant
                0b00 when isVector => Arm64Mnemonic.LDR, //128-bit load
                0b10 or 0b11 => throw new Arm64UndefinedInstructionException("Load/store register from register offset: opc 0b11 unallocated for size 0b1x"),
                _ when isVector => throw new Arm64UndefinedInstructionException("Load/store register from register offset: opc 0b11 unallocated for vectors when size > 0"),
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };

        var isShiftedRegister = option == 0b011;

        if (mnemonic == Arm64Mnemonic.PRFM)
        {
            //Prefetch with a register offset: Op0 is the prefetch operation immediate;
            //PRFM always behaves as the 64-bit size so S shifts by 3
            var prfShiftAmount = sFlag ? 3 : 0;
            var prfAddendBase = option.TestBit(0) ? Arm64Register.X0 : Arm64Register.W0;
            return new()
            {
                Mnemonic = Arm64Mnemonic.PRFM,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = rt,
                Op1Kind = Arm64OperandKind.Memory,
                MemBase = Arm64Register.X0 + rn,
                MemAddendReg = prfAddendBase + rm,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemExtendType = isShiftedRegister ? Arm64ExtendType.NONE : (Arm64ExtendType)option,
                MemShiftType = isShiftedRegister && sFlag ? Arm64ShiftType.LSL : Arm64ShiftType.NONE,
                MemExtendOrShiftAmount = prfShiftAmount,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            };
        }

        var baseReg = mnemonic switch
        {
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector && opc is 0 or 1 => size switch
            {
                0 => Arm64Register.B0,
                1 => Arm64Register.H0,
                2 => Arm64Register.S0,
                3 => Arm64Register.D0,
                _ => throw new("Impossible size")
            },
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector => Arm64Register.V0, //128-bit vector
            Arm64Mnemonic.STRB or Arm64Mnemonic.LDRB or Arm64Mnemonic.STRH or Arm64Mnemonic.LDRH => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR => Arm64Register.X0,
            Arm64Mnemonic.LDRSB or Arm64Mnemonic.LDRSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDRSB or Arm64Mnemonic.LDRSH => Arm64Register.W0,
            Arm64Mnemonic.LDRSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };

        var secondReg64Bit = option.TestBit(0);
        var secondRegBase = secondReg64Bit ? Arm64Register.X0 : Arm64Register.W0;
        var extendKind = (Arm64ExtendType)option;
        //Extended register: Mnemonic Wt, [Xn, Xm|Wm, ExtendKind Amount]
        //Shifted register: Mnemonic Wt, [Xn, Xm|Wm, LSL Amount]

        var shiftAmount = 0;
        if (sFlag)
        {
            //S bit set, amount is size-dependent and applies to both shifted and extended forms
            shiftAmount = size switch
            {
                0b00 when isVector && opc is 0b10 or 0b11 => 4, //128-bit variant
                0b00 => 0, //8-bit variant, vector or otherwise
                0b01 => 1,
                0b10 => 2,
                0b11 => 3,
                _ => throw new("Impossible size")
            };
        }
        
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            Op0Reg = baseReg + rt,
            MemBase = Arm64Register.X0 + rn,
            MemAddendReg = secondRegBase + rm,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
            MemExtendType = isShiftedRegister ? Arm64ExtendType.NONE : extendKind,
            MemShiftType = isShiftedRegister && sFlag ? Arm64ShiftType.LSL : Arm64ShiftType.NONE, //lsl without the s flag is just a plain register offset

            MemExtendOrShiftAmount = shiftAmount,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromPac(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.PointerAuthentication,
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromImmUnscaled(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26);
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var imm9 = (instruction >> 12) & 0b1_1111_1111; //Bits 12-20
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4
        
        if(size is 1 or 3 && isVector && opc > 1)
            throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc > 1 unallocated for vectors when size > 1");
        
        //Here we go with this dance again...
        var mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.STURB,
                0b01 when !isVector => Arm64Mnemonic.STURH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.STUR,
                _ when isVector => Arm64Mnemonic.STUR,
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDURB,
                0b01 when !isVector => Arm64Mnemonic.LDURH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.LDUR,
                _ when isVector => Arm64Mnemonic.LDUR,
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDURSB, //64-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDURSH, //64-bit variant
                0b10 when !isVector => Arm64Mnemonic.LDURSW,
                0b11 when !isVector => Arm64Mnemonic.PRFUM, //prefetch, unscaled signed immediate
                0b00 when isVector => Arm64Mnemonic.STUR, //128-bit store
                _ when isVector => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unscaled): opc 0b10 unallocated for vectors when size > 0"),
                _ => throw new($"Impossible size: {size}")
            },
            0b11 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDURSB, //32-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDURSH, //32-bit variant
                0b10 when !isVector => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unscaled): opc 0b11 unallocated for size 0b10"),
                0b00 when isVector => Arm64Mnemonic.LDUR, //128-bit store
                0b11 => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unscaled): opc 0b11 unallocated for size 0b11"),
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };
        
        if (mnemonic == Arm64Mnemonic.PRFUM)
        {
            var prfumOffset = Arm64CommonUtils.SignExtend(imm9, 9, 64);
            return new()
            {
                Mnemonic = Arm64Mnemonic.PRFUM,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = rt,
                Op1Kind = Arm64OperandKind.Memory,
                MemBase = Arm64Register.X0 + rn,
                MemOffset = prfumOffset,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            };
        }

        var baseReg = mnemonic switch
        {
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR when isVector && opc is 0 or 1 => size switch
            {
                0 => Arm64Register.B0,
                1 => Arm64Register.H0,
                2 => Arm64Register.S0,
                3 => Arm64Register.D0,
                _ => throw new("Impossible size")
            },
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR when isVector => Arm64Register.V0, //128-bit vector
            Arm64Mnemonic.STURB or Arm64Mnemonic.LDURB or Arm64Mnemonic.STURH or Arm64Mnemonic.LDURH => Arm64Register.W0,
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR => Arm64Register.X0,
            Arm64Mnemonic.LDURSB or Arm64Mnemonic.LDURSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDURSB or Arm64Mnemonic.LDURSH => Arm64Register.W0,
            Arm64Mnemonic.LDURSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };
        
        var regT = baseReg + rt;
        var regN = Arm64Register.X0 + rn;
        
        //Sign extend imm9 to 64-bit
        var immediate = Arm64CommonUtils.SignExtend(imm9, 9, 64);
        
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            Op0Reg = regT,
            MemBase = regN,
            MemOffset = immediate,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreRegisterUnprivileged(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreExclusivePair(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31: 0b10 = 32-bit pairs, 0b11 = 64-bit pairs
        var isLoad = instruction.TestBit(22);
        var o0 = instruction.TestBit(15); //acquire
        var rs = (int)(instruction >> 16) & 0b1_1111; //Bits 16-20: status register on stores
        var rt2 = (int)(instruction >> 10) & 0b1_1111; //Bits 10-14: second data register
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rt = (int)instruction & 0b1_1111;

        var dataBase = size == 0b10 ? Arm64Register.W0 : Arm64Register.X0;
        var mnemonic = (isLoad, o0) switch
        {
            (false, false) => Arm64Mnemonic.STXP,
            (false, true) => Arm64Mnemonic.STLXP,
            (true, false) => Arm64Mnemonic.LDXP,
            (true, true) => Arm64Mnemonic.LDAXP,
        };

        if (isLoad)
            return new()
            {
                Mnemonic = mnemonic,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = dataBase + rt,
                Op1Reg = dataBase + rt2,
                MemBase = Arm64Register.X0 + rn,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
            };

        //stores prepend a status result register: STXP Ws, Wt1, Wt2, [Xn]
        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = Arm64OperandKind.Memory,
            Op0Reg = Arm64Register.W0 + rs,
            Op1Reg = dataBase + rt,
            Op2Reg = dataBase + rt2,
            MemBase = Arm64Register.X0 + rn,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
        };
    }
}
