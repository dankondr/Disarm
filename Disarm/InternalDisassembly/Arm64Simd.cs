namespace Disarm.InternalDisassembly;

internal static class Arm64Simd
{
    //I hate this entire table.
    
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op0 = (instruction >> 28) & 0b1111; //Bits 28-31
        //25-27 must be 111
        var op1 = (instruction >> 23) & 0b11; //Bits 23-24
        var op2 = (instruction >> 19) & 0b1111; //Bits 19-22
        var op3 = (instruction >> 10) & 0b1_1111_1111; //Bits 10-18

        var op1Hi = op1 >> 1;

        //Concrete values or one-masked-bit for op0
        switch (op0)
        {
            case 0b0100 when op1Hi == 0 && op2.TestPattern(0b111, 0b101) && op3.TestPattern(0b110000011, 0b10):
                return CryptoAes(instruction);
            case 0b0101 when op1Hi == 0 && op2.TestPattern(0b111, 0b101) && op3.TestPattern(0b110000011, 0b10):
                return CryptoTwoRegSha(instruction);
            case 0b0101 when op1Hi == 0 && op2.TestPattern(0b0100, 0) && op3.TestPattern(0b100011, 0):
                return CryptoThreeRegSha(instruction);
            case 0b0101 or 0b0111 when op1 == 0 && op2.TestPattern(0b1100, 0) && op3.TestPattern(0b100001, 1):
                return AdvancedSimdScalarCopy(instruction);
        }

        //Masks for op0
        if (op0.TestPattern(0b1001, 0))
        {
            //0xx0 family: Advanced SIMD (non-scalar)
            return Arm64NonScalarAdvancedSimd.Disassemble(instruction);
        }

        if (op0.TestPattern(0b1101, 0b0101))
        {
            //01x1 family: Advanced SIMD (scalar)
            return Arm64ScalarAdvancedSimd.Disassemble(instruction);
        }

        if (op0 == 0b1100)
        {
            //TODO Cryptographic two, three, or four reg
            return new()
            {
                Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
                MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic, 
            };
        }

        if (op0.TestPattern(0b0101, 0b0001))
        {
            //x0x1: Floating point family - either conversion two/from integer/fixed-point, or some general floating-point instruction
            
            if (op1.TestBit(1))
                //Only one with bit 24 set
                return Arm64FloatingPoint.DataProcessingThreeSource(instruction);

            //Get the two conversion types out first
            
            if (!op2.TestBit(2))
                //Only one with bit 20 clear
                return Arm64FloatingPoint.ConversionToAndFromFixedPoint(instruction);

            if ((op3 & 0b11_1111) == 0)
                return Arm64FloatingPoint.ConversionToAndFromInteger(instruction);

            if ((op3 & 0b1_1111) == 0b1_0000)
                return Arm64FloatingPoint.DataProcessingOneSource(instruction);
            
            if((op3 & 0b1111) == 0b1000)
                return Arm64FloatingPoint.Compare(instruction);

            if ((op3 & 0b111) == 0b100)
                return Arm64FloatingPoint.Immediate(instruction);

            return (op3 & 0b11) switch
            {
                0b01 => Arm64FloatingPoint.ConditionalCompare(instruction),
                0b10 => Arm64FloatingPoint.DataProcessingTwoSource(instruction),
                0b11 => Arm64FloatingPoint.ConditionalSelect(instruction),
                _ => throw new("Impossible op3"),
            };
        }

        throw new Arm64UndefinedInstructionException($"Unimplemented SIMD instruction. Op0: {op0}, Op1: {op1}, Op2: {op2}, Op3: {op3}");
    }


    private static Arm64Instruction CryptoAes(uint instruction)
    {
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var opcode = (instruction >> 12) & 0b1_1111; // Bits 12-16
        var rn = (int) (instruction >> 5) & 0b11111; // Bits 5-9
        var rd = (int) instruction & 0b11111; // Bits 0-4
        
        if(size != 0)
            throw new Arm64UndefinedInstructionException("AES instruction with size != 0");

        if (opcode.TestBit(3) || instruction.TestBit(4) || (instruction >> 2) == 0)
            throw new Arm64UndefinedInstructionException($"AES: Reserved opcode 0x{opcode:X}");

        return new()
        {
            Mnemonic = opcode switch
            {
                0b00100 => Arm64Mnemonic.AESE,
                0b00101 => Arm64Mnemonic.AESD,
                0b00110 => Arm64Mnemonic.AESMC,
                0b00111 => Arm64Mnemonic.AESIMC,
                _ => throw new Arm64UndefinedInstructionException($"AES: bad opcode {opcode}")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.V0 + rd,
            Op1Reg = Arm64Register.V0 + rn,
            Op0Arrangement = Arm64ArrangementSpecifier.SixteenB,
            Op1Arrangement = Arm64ArrangementSpecifier.SixteenB,
        };
    }

    private static Arm64Instruction CryptoTwoRegSha(uint instruction)
    {
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var opcode = (instruction >> 12) & 0b1_1111; // Bits 12-16
        var rn = (int) (instruction >> 5) & 0b11111; // Bits 5-9
        var rd = (int) instruction & 0b11111; // Bits 0-4
        
        if(size != 0)
            throw new Arm64UndefinedInstructionException("SHA instruction with size != 0");
        
        return new()
        {
            Mnemonic = opcode switch
            {
                0b00000 => Arm64Mnemonic.SHA1H,
                0b00001 => Arm64Mnemonic.SHA1SU1,
                0b00010 => Arm64Mnemonic.SHA256SU0,
                _ => throw new Arm64UndefinedInstructionException($"SHA: bad opcode {opcode}")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic, 
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = opcode switch
            {
                0b00000 => Arm64Register.S0 + rd,
                _ => Arm64Register.V0 + rd,
            },
            Op1Reg = opcode switch
            {
                0b00000 => Arm64Register.S0 + rn,
                _ => Arm64Register.V0 + rn,
            },
            Op0Arrangement = opcode switch
            {
                0b00000 => Arm64ArrangementSpecifier.None,
                _ => Arm64ArrangementSpecifier.FourS,
            },
            Op1Arrangement = opcode switch
            {
                0b00000 => Arm64ArrangementSpecifier.None,
                _ => Arm64ArrangementSpecifier.FourS,
            },
        };
    }

    private static Arm64Instruction CryptoThreeRegSha(uint instruction)
    {
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var opcode = (instruction >> 12) & 0b111; // Bits 12-14
        var rm = (int) (instruction >> 16) & 0b11111; // Bits 16-20
        var rn = (int) (instruction >> 5) & 0b11111; // Bits 5-9
        var rd = (int) instruction & 0b11111; // Bits 0-4
        
        if(size != 0)
            throw new Arm64UndefinedInstructionException("SHA instruction with size != 0");
        
        return new()
        {
            Mnemonic = opcode switch
            {
                0b000 => Arm64Mnemonic.SHA1C,
                0b001 => Arm64Mnemonic.SHA1P,
                0b010 => Arm64Mnemonic.SHA1M,
                0b011 => Arm64Mnemonic.SHA1SU0,
                0b100 => Arm64Mnemonic.SHA256H,
                0b101 => Arm64Mnemonic.SHA256H2,
                0b110 => Arm64Mnemonic.SHA256SU1,
                _ => throw new Arm64UndefinedInstructionException("Bad opcode")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic, 
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.V0 + rd,
            Op1Reg = opcode switch
            {
                0b000 or 0b001 or 0b010 => Arm64Register.S0 + rn,
                _ => Arm64Register.V0 + rn,
            },
            Op2Reg = Arm64Register.V0 + rm,
            Op0Arrangement = opcode switch
            {
                0b011 or 0b110 => Arm64ArrangementSpecifier.FourS,
                _ => Arm64ArrangementSpecifier.None,
            },
            Op1Arrangement = opcode switch
            {
                0b011 or 0b110 => Arm64ArrangementSpecifier.FourS,
                _ => Arm64ArrangementSpecifier.None,
            },
            Op2Arrangement = Arm64ArrangementSpecifier.FourS,
        };
    }

    internal static Arm64Instruction LoadStoreMultipleStructures(uint instruction) => LoadStoreMultipleStructuresImpl(instruction, false);

    internal static Arm64Instruction LoadStoreMultipleStructuresPostIndexed(uint instruction) => LoadStoreMultipleStructuresImpl(instruction, true);

    private static Arm64Instruction LoadStoreMultipleStructuresImpl(uint instruction, bool postIndexed)
    {
        var q = instruction.TestBit(30);
        var isLoad = instruction.TestBit(22);
        var rm = (int)(instruction >> 16) & 0b1_1111; //Bits 16-20
        var opcode = (instruction >> 12) & 0b1111; //Bits 12-15
        var size = (instruction >> 10) & 0b11; //Bits 10-11
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4

        if (instruction.TestBit(25))
            throw new Arm64UndefinedInstructionException("Load/store multiple structures: bit 25 must be zero");

        var (mnemonic, numRegs) = opcode switch
        {
            0b0000 => (isLoad ? Arm64Mnemonic.LD4 : Arm64Mnemonic.ST4, 4),
            0b0010 => (isLoad ? Arm64Mnemonic.LD1 : Arm64Mnemonic.ST1, 4),
            0b0100 => (isLoad ? Arm64Mnemonic.LD3 : Arm64Mnemonic.ST3, 3),
            0b0110 => (isLoad ? Arm64Mnemonic.LD1 : Arm64Mnemonic.ST1, 3),
            0b0111 => (isLoad ? Arm64Mnemonic.LD1 : Arm64Mnemonic.ST1, 1),
            0b1000 => (isLoad ? Arm64Mnemonic.LD2 : Arm64Mnemonic.ST2, 2),
            0b1010 => (isLoad ? Arm64Mnemonic.LD1 : Arm64Mnemonic.ST1, 2),
            _ => throw new Arm64UndefinedInstructionException($"Load/store multiple structures: opcode 0x{opcode:X} is unallocated")
        };

        if (size == 0b11 && !q && mnemonic is not (Arm64Mnemonic.LD1 or Arm64Mnemonic.ST1))
            throw new Arm64UndefinedInstructionException("Load/store multiple structures: 1D arrangement is only valid for LD1/ST1");

        var arrangement = size switch
        {
            0b00 => q ? Arm64ArrangementSpecifier.SixteenB : Arm64ArrangementSpecifier.EightB,
            0b01 => q ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH,
            0b10 => q ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS,
            0b11 => q ? Arm64ArrangementSpecifier.TwoD : Arm64ArrangementSpecifier.OneD,
            _ => throw new("Impossible size")
        };

        var insn = new Arm64Instruction
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.V0 + rt,
            Op0Arrangement = arrangement,
            MemBase = Arm64Register.X0 + rn,
            MemIndexMode = postIndexed ? Arm64MemoryIndexMode.PostIndex : Arm64MemoryIndexMode.Offset,
            MnemonicCategory = Arm64MnemonicCategory.SimdStructureLoadOrStore,
        };

        if (numRegs > 1)
        {
            insn.Op1Kind = Arm64OperandKind.Register;
            insn.Op1Reg = Arm64Register.V0 + (rt + 1) % 32; //register lists wrap
            insn.Op1Arrangement = arrangement;
        }

        if (numRegs > 2)
        {
            insn.Op2Kind = Arm64OperandKind.Register;
            insn.Op2Reg = Arm64Register.V0 + (rt + 2) % 32;
            insn.Op2Arrangement = arrangement;
        }

        if (numRegs > 3)
        {
            insn.Op3Kind = Arm64OperandKind.Register;
            insn.Op3Reg = Arm64Register.V0 + (rt + 3) % 32;
            insn.Op3Arrangement = arrangement;
        }

        //memory operand goes in the slot after the last register
        switch (numRegs)
        {
            case 1:
                insn.Op1Kind = Arm64OperandKind.Memory;
                break;
            case 2:
                insn.Op2Kind = Arm64OperandKind.Memory;
                break;
            case 3:
                insn.Op3Kind = Arm64OperandKind.Memory;
                break;
            default:
                insn.Op4Kind = Arm64OperandKind.Memory;
                break;
        }

        if (postIndexed)
        {
            if (rm == 0b1_1111)
                insn.MemOffset = (q ? 16 : 8) * numRegs; //post-index by immediate
            else
                insn.MemAddendReg = Arm64Register.X0 + rm; //post-index by register
        }

        return insn;
    }

    internal static Arm64Instruction LoadStoreSingleStructure(uint instruction) => LoadStoreSingleStructureImpl(instruction, false);

    internal static Arm64Instruction LoadStoreSingleStructurePostIndexed(uint instruction) => LoadStoreSingleStructureImpl(instruction, true);

    private static Arm64Instruction LoadStoreSingleStructureImpl(uint instruction, bool postIndexed)
    {
        var q = instruction.TestBit(30);
        var isLoad = instruction.TestBit(22);
        var r = instruction.TestBit(21);
        var rm = (int)(instruction >> 16) & 0b1_1111; //post-indexed only
        var opcode = (instruction >> 13) & 0b111;
        var s = instruction.TestBit(12);
        var size = (instruction >> 10) & 0b11;
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rt = (int)instruction & 0b1_1111;

        if (instruction.TestBit(25))
            throw new Arm64UndefinedInstructionException("Load/store single structure: bit 25 must be zero");

        if (!postIndexed && (instruction >> 16 & 0b1_1111) != 0)
            throw new Arm64UndefinedInstructionException("Load/store single structure: bits 16-20 must be zero");

        //Replicate loads (LD1R-LD4R) fill an entire vector from a single element
        if (opcode >= 0b110)
        {
            if (!isLoad)
                throw new Arm64UndefinedInstructionException("Load/store single structure: stores do not have a replicate form");

            if (s)
                throw new Arm64UndefinedInstructionException("Load/store single structure: S must be zero for replicate loads");

            var (repMnemonic, numReplicateRegs) = (r, opcode) switch
            {
                (false, 0b110) => (Arm64Mnemonic.LD1R, 1),
                (true, 0b110) => (Arm64Mnemonic.LD2R, 2),
                (false, 0b111) => (Arm64Mnemonic.LD3R, 3),
                (true, 0b111) => (Arm64Mnemonic.LD4R, 4),
                _ => throw new("Impossible replicate opcode")
            };

            var arrangement = size switch
            {
                0b00 => q ? Arm64ArrangementSpecifier.SixteenB : Arm64ArrangementSpecifier.EightB,
                0b01 => q ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH,
                0b10 => q ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS,
                0b11 when q => Arm64ArrangementSpecifier.TwoD,
                _ => Arm64ArrangementSpecifier.OneD,
            };

            var insn = new Arm64Instruction
            {
                Mnemonic = repMnemonic,
                MnemonicCategory = Arm64MnemonicCategory.SimdStructureLoadOrStore,
                Op0Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.V0 + rt,
                Op0Arrangement = arrangement,
                MemBase = Arm64Register.X0 + rn,
                MemIndexMode = postIndexed ? Arm64MemoryIndexMode.PostIndex : Arm64MemoryIndexMode.Offset,
            };

            //each additional register takes the next operand slot
            for (var i = 1; i < numReplicateRegs; i++)
            {
                var kind = Arm64OperandKind.Register;
                var reg = Arm64Register.V0 + (rt + i) % 32;
                switch (i)
                {
                    case 1:
                        insn.Op1Kind = kind;
                        insn.Op1Reg = reg;
                        insn.Op1Arrangement = arrangement;
                        break;
                    case 2:
                        insn.Op2Kind = kind;
                        insn.Op2Reg = reg;
                        insn.Op2Arrangement = arrangement;
                        break;
                    default:
                        insn.Op3Kind = kind;
                        insn.Op3Reg = reg;
                        insn.Op3Arrangement = arrangement;
                        break;
                }
            }

            switch (numReplicateRegs)
            {
                case 1:
                    insn.Op1Kind = Arm64OperandKind.Memory;
                    break;
                case 2:
                    insn.Op2Kind = Arm64OperandKind.Memory;
                    break;
                case 3:
                    insn.Op3Kind = Arm64OperandKind.Memory;
                    break;
                default:
                    insn.Op4Kind = Arm64OperandKind.Memory;
                    break;
            }

            if (postIndexed)
            {
                if (rm == 0b1_1111)
                    insn.MemOffset = (1 << (int)size) * numReplicateRegs; //element size in bytes, times register count
                else
                    insn.MemAddendReg = Arm64Register.X0 + rm;
            }

            return insn;
        }

        //LD1-LD4/ST1-ST4 single-element forms: opc<0> selects 1/3 or 2/4 registers
        var numRegs = r
            ? (opcode & 1) == 0 ? 2 : 4
            : (opcode & 1) == 0 ? 1 : 3;

        var mnemonic = (isLoad, numRegs) switch
        {
            (true, 1) => Arm64Mnemonic.LD1,
            (true, 2) => Arm64Mnemonic.LD2,
            (true, 3) => Arm64Mnemonic.LD3,
            (true, 4) => Arm64Mnemonic.LD4,
            (false, 1) => Arm64Mnemonic.ST1,
            (false, 2) => Arm64Mnemonic.ST2,
            (false, 3) => Arm64Mnemonic.ST3,
            (false, 4) => Arm64Mnemonic.ST4,
            _ => throw new("Impossible register count")
        };

        //opc<2:1> selects the element width; the index comes from Q:S:size
        Arm64VectorElementWidth elementWidth;
        int index;
        int elementBytes;
        switch (opcode >> 1)
        {
            case 0b00:
                elementWidth = Arm64VectorElementWidth.B;
                index = (q ? 8 : 0) | (s ? 4 : 0) | (int)size;
                elementBytes = 1;
                break;
            case 0b01:
                if ((size & 1) != 0)
                    throw new Arm64UndefinedInstructionException("Load/store single structure: size<0> must be zero for h elements");
                elementWidth = Arm64VectorElementWidth.H;
                index = (q ? 4 : 0) | (s ? 2 : 0) | (int)(size >> 1);
                elementBytes = 2;
                break;
            default:
                if (size == 0b00)
                {
                    elementWidth = Arm64VectorElementWidth.S;
                    index = (q ? 2 : 0) | (s ? 1 : 0);
                    elementBytes = 4;
                }
                else if (size == 0b01)
                {
                    if (s)
                        throw new Arm64UndefinedInstructionException("Load/store single structure: S must be zero for d elements");
                    elementWidth = Arm64VectorElementWidth.D;
                    index = q ? 1 : 0;
                    elementBytes = 8;
                }
                else
                    throw new Arm64UndefinedInstructionException("Load/store single structure: d elements require size == 0b01");
                break;
        }

        var result = new Arm64Instruction
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.SimdStructureLoadOrStore,
            Op0Kind = Arm64OperandKind.VectorRegisterElement,
            Op0Reg = Arm64Register.V0 + rt,
            Op0VectorElement = new(elementWidth, index),
            MemBase = Arm64Register.X0 + rn,
            MemIndexMode = postIndexed ? Arm64MemoryIndexMode.PostIndex : Arm64MemoryIndexMode.Offset,
        };

        for (var i = 1; i < numRegs; i++)
        {
            var reg = Arm64Register.V0 + (rt + i) % 32;
            var element = new Arm64VectorElement(elementWidth, index);
            switch (i)
            {
                case 1:
                    result.Op1Kind = Arm64OperandKind.VectorRegisterElement;
                    result.Op1Reg = reg;
                    result.Op1VectorElement = element;
                    break;
                case 2:
                    result.Op2Kind = Arm64OperandKind.VectorRegisterElement;
                    result.Op2Reg = reg;
                    result.Op2VectorElement = element;
                    break;
                default:
                    result.Op3Kind = Arm64OperandKind.VectorRegisterElement;
                    result.Op3Reg = reg;
                    result.Op3VectorElement = element;
                    break;
            }
        }

        switch (numRegs)
        {
            case 1:
                result.Op1Kind = Arm64OperandKind.Memory;
                break;
            case 2:
                result.Op2Kind = Arm64OperandKind.Memory;
                break;
            case 3:
                result.Op3Kind = Arm64OperandKind.Memory;
                break;
            default:
                result.Op4Kind = Arm64OperandKind.Memory;
                break;
        }

        if (postIndexed)
        {
            if (rm == 0b1_1111)
                result.MemOffset = elementBytes * numRegs;
            else
                result.MemAddendReg = Arm64Register.X0 + rm;
        }

        return result;
    }
    
    public static Arm64Instruction AdvancedSimdScalarCopy(uint instruction)
    {
        var op = instruction.TestBit(29);
        var imm5 = (instruction >> 16) & 0b1_1111;
        var imm4 = (instruction >> 11) & 0b1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(op)
            throw new Arm64UndefinedInstructionException("Advanced SIMD: scalar copy: op flag is reserved");
        
        if(imm4 != 0)
            throw new Arm64UndefinedInstructionException("Advanced SIMD: scalar copy: all bits of imm4 are reserved");
        
        //There's actually only one instruction here lol, DUP (element)
        //Which in turn is actually just an alias of MOV (scalar)
        //Still, I'll disassemble it as DUP and implement the alias properly
        
        var baseDestReg = imm5.TestBit(0) 
            ? Arm64Register.B0 : imm5.TestBit(1)
            ? Arm64Register.H0 : imm5.TestBit(2)
            ? Arm64Register.S0 : imm5.TestBit(3)
            ? Arm64Register.D0 : throw new Arm64UndefinedInstructionException("Advanced SIMD: scalar copy: high bit of imm5 is reserved");

        var destReg = baseDestReg + rd;
        var srcReg = Arm64Register.V0 + rn;

        var srcVectorElementWidth = baseDestReg switch
        {
            Arm64Register.B0 => Arm64VectorElementWidth.B,
            Arm64Register.H0 => Arm64VectorElementWidth.H,
            Arm64Register.S0 => Arm64VectorElementWidth.S,
            Arm64Register.D0 => Arm64VectorElementWidth.D,
            _ => throw new("Impossible baseDestReg")
        };

        var srcElementIndex = srcVectorElementWidth switch
        {
            Arm64VectorElementWidth.B => imm5 >> 1,
            Arm64VectorElementWidth.H => imm5 >> 2,
            Arm64VectorElementWidth.S => imm5 >> 3,
            Arm64VectorElementWidth.D => imm5 >> 4,
            _ => throw new("Impossible srcVectorElementWidth")
        };

        return new()
        {
            Mnemonic = Arm64Mnemonic.DUP,
            Op0Kind = Arm64OperandKind.Register,
            Op0Reg = destReg,
            Op1Kind = Arm64OperandKind.VectorRegisterElement,
            Op1Reg = srcReg,
            Op1VectorElement = new(srcVectorElementWidth, (int)srcElementIndex),
            MnemonicCategory = Arm64MnemonicCategory.SimdRegisterToRegister,
        };
    }
}
