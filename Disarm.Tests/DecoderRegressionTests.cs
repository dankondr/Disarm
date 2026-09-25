using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

/// <summary>
/// Table-driven regression tests for decoder gaps found by diffing Disarm against llvm-objdump.
/// Every raw word below was verified against LLVM 20 disassembly (mnemonic + all operand fields).
/// </summary>
public class DecoderRegressionTests : BaseDisarmTest
{
    public DecoderRegressionTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    #region Advanced SIMD shift by immediate

    //sshr v0.8b, v1.8b, #8
    [Theory]
    [InlineData(0x0F080420U, Arm64Mnemonic.SSHR)]
    [InlineData(0x0F081420U, Arm64Mnemonic.SSRA)]
    [InlineData(0x2F080420U, Arm64Mnemonic.USHR)]
    [InlineData(0x2F081420U, Arm64Mnemonic.USRA)]
    [InlineData(0x2F082420U, Arm64Mnemonic.URSHR)]
    [InlineData(0x2F104420U, Arm64Mnemonic.SRI)]
    [InlineData(0x2F106420U, Arm64Mnemonic.SQSHLU)]
    public void TestVectorShiftByImmediate_Simple(uint raw, Arm64Mnemonic mnemonic)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64OperandKind.Register, result.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, result.Op1Kind);
        Assert.Equal(Arm64OperandKind.Immediate, result.Op2Kind);
        Assert.Equal(Arm64Register.V0, result.Op0Reg);
        Assert.Equal(Arm64Register.V1, result.Op1Reg);
    }

    //sshll v0.8h, v1.8b, #0 / ushll v0.8h, v1.8b, #0 — dest arrangement wider than source
    [Theory]
    [InlineData(0x0F08A420U, Arm64Mnemonic.SSHLL, Arm64ArrangementSpecifier.EightH, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x2F08A420U, Arm64Mnemonic.USHLL, Arm64ArrangementSpecifier.EightH, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x2E213820U, Arm64Mnemonic.SHLL, Arm64ArrangementSpecifier.EightH, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x2EA13820U, Arm64Mnemonic.SHLL, Arm64ArrangementSpecifier.TwoD, Arm64ArrangementSpecifier.TwoS)]
    public void TestVectorShiftByImmediate_Long(uint raw, Arm64Mnemonic mnemonic, Arm64ArrangementSpecifier destArr, Arm64ArrangementSpecifier srcArr)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(destArr, result.Op0Arrangement);
        Assert.Equal(srcArr, result.Op1Arrangement);
    }

    //shrn v0.8b, v1.8h, #8 — narrowing: dest half-width of source
    [Theory]
    [InlineData(0x0F088420U, Arm64Mnemonic.SHRN)]
    [InlineData(0x0F088C20U, Arm64Mnemonic.RSHRN)]
    [InlineData(0x0F089420U, Arm64Mnemonic.SQSHRN)]
    [InlineData(0x0F089C20U, Arm64Mnemonic.SQRSHRN)]
    [InlineData(0x2F088420U, Arm64Mnemonic.SQSHRUN)]
    [InlineData(0x2F088C20U, Arm64Mnemonic.SQRSHRUN)]
    [InlineData(0x2F089420U, Arm64Mnemonic.UQSHRN)]
    [InlineData(0x2F089C20U, Arm64Mnemonic.UQRSHRN)]
    public void TestVectorShiftByImmediate_Narrow(uint raw, Arm64Mnemonic mnemonic)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64ArrangementSpecifier.EightB, result.Op0Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.EightH, result.Op1Arrangement);
        Assert.Equal(8, result.Op2Imm);
    }

    //sli/sqshlu shift semantics: shift amount printed as imm - esize
    [Fact]
    public void TestVectorShiftByImmediate_LeftShift()
    {
        //sli v0.8b, v1.8b, #0
        var result = DisassembleAndCheckMnemonic(0x2F085420U, Arm64Mnemonic.SLI);
        Assert.Equal(0, result.Op2Imm);
        Assert.Equal(Arm64ArrangementSpecifier.EightB, result.Op0Arrangement);
    }

    //fcvtzs/scvtf/ucvtf/fcvtzu in the shift class
    [Theory]
    [InlineData(0x0F20FC20U, Arm64Mnemonic.FCVTZS)]
    [InlineData(0x0F20E420U, Arm64Mnemonic.SCVTF)]
    [InlineData(0x2EA1B820U, Arm64Mnemonic.FCVTZU)]
    [InlineData(0x2E21D820U, Arm64Mnemonic.UCVTF)]
    public void TestVectorShiftByImmediate_FloatConvert(uint raw, Arm64Mnemonic mnemonic)
        => DisassembleAndCheckMnemonic(raw, mnemonic);

    //immh == 0 is reserved in this class (goes to modified-immediate instead)
    [Theory]
    [InlineData(0x0F00C420U)] //movi modified-immediate, NOT a shift — must not decode as SSHR
    public void TestVectorShiftByImmediate_Reserved(uint raw)
        => Assert.Equal(Arm64Mnemonic.MOVI, Disassembler.DisassembleSingleInstruction(raw).Mnemonic);

    #endregion

    #region Advanced SIMD two-register misc

    [Theory]
    [InlineData(0x2E205820U, Arm64Mnemonic.MVN, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x6E605820U, Arm64Mnemonic.RBIT, Arm64ArrangementSpecifier.SixteenB)]
    [InlineData(0x0E205820U, Arm64Mnemonic.CNT, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0E204820U, Arm64Mnemonic.CLS, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x2E204820U, Arm64Mnemonic.CLZ, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0E207820U, Arm64Mnemonic.SQABS, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x2E207820U, Arm64Mnemonic.SQNEG, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0E603820U, Arm64Mnemonic.SUQADD, Arm64ArrangementSpecifier.FourH)]
    [InlineData(0x2E203820U, Arm64Mnemonic.USQADD, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0E608820U, Arm64Mnemonic.CMGT, Arm64ArrangementSpecifier.FourH)]
    [InlineData(0x0E209820U, Arm64Mnemonic.CMEQ, Arm64ArrangementSpecifier.EightB)]
    public void TestTwoRegMisc_Integer(uint raw, Arm64Mnemonic mnemonic, Arm64ArrangementSpecifier arrangement)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64Register.V0, result.Op0Reg);
        Assert.Equal(Arm64Register.V1, result.Op1Reg);
        Assert.Equal(arrangement, result.Op0Arrangement);
        Assert.Equal(arrangement, result.Op1Arrangement);
    }

    //Pairwise lengthening: destination is wider than source
    [Theory]
    [InlineData(0x0E202820U, Arm64Mnemonic.SADDLP, Arm64ArrangementSpecifier.FourH, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x2E202820U, Arm64Mnemonic.UADDLP, Arm64ArrangementSpecifier.FourH, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0E206820U, Arm64Mnemonic.SADALP, Arm64ArrangementSpecifier.FourH, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x2E206820U, Arm64Mnemonic.UADALP, Arm64ArrangementSpecifier.FourH, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0EA02820U, Arm64Mnemonic.SADDLP, Arm64ArrangementSpecifier.OneD, Arm64ArrangementSpecifier.TwoS)]
    public void TestTwoRegMisc_Long(uint raw, Arm64Mnemonic mnemonic, Arm64ArrangementSpecifier destArr, Arm64ArrangementSpecifier srcArr)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(destArr, result.Op0Arrangement);
        Assert.Equal(srcArr, result.Op1Arrangement);
    }

    //fcvtn/fcvtl: narrow/widen floating-point conversions
    [Theory]
    [InlineData(0x0E216820U, Arm64Mnemonic.FCVTN, Arm64ArrangementSpecifier.FourH, Arm64ArrangementSpecifier.FourS)]
    [InlineData(0x0E217820U, Arm64Mnemonic.FCVTL, Arm64ArrangementSpecifier.FourS, Arm64ArrangementSpecifier.FourH)]
    [InlineData(0x0E616820U, Arm64Mnemonic.FCVTN, Arm64ArrangementSpecifier.TwoS, Arm64ArrangementSpecifier.TwoD)]
    [InlineData(0x0E617820U, Arm64Mnemonic.FCVTL, Arm64ArrangementSpecifier.TwoD, Arm64ArrangementSpecifier.TwoS)]
    [InlineData(0x0EA16820U, Arm64Mnemonic.BFCVTN, Arm64ArrangementSpecifier.FourH, Arm64ArrangementSpecifier.FourS)]
    public void TestTwoRegMisc_FloatConvert(uint raw, Arm64Mnemonic mnemonic, Arm64ArrangementSpecifier destArr, Arm64ArrangementSpecifier srcArr)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(destArr, result.Op0Arrangement);
        Assert.Equal(srcArr, result.Op1Arrangement);
    }

    //Floating-point unary/compares: sz selects s or d elements
    [Theory]
    [InlineData(0x0EA0C820U, Arm64Mnemonic.FCMGT, Arm64ArrangementSpecifier.TwoS)]
    [InlineData(0x0EA0F820U, Arm64Mnemonic.FABS, Arm64ArrangementSpecifier.TwoS)]
    [InlineData(0x2EA0F820U, Arm64Mnemonic.FNEG, Arm64ArrangementSpecifier.TwoS)]
    [InlineData(0x2EA1D820U, Arm64Mnemonic.FRSQRTE, Arm64ArrangementSpecifier.TwoS)]
    [InlineData(0x2EA1F820U, Arm64Mnemonic.FSQRT, Arm64ArrangementSpecifier.TwoS)]
    public void TestTwoRegMisc_Float(uint raw, Arm64Mnemonic mnemonic, Arm64ArrangementSpecifier arrangement)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(arrangement, result.Op0Arrangement);
        Assert.Equal(arrangement, result.Op1Arrangement);
    }

    //1d floating-point arrangement is reserved in this class
    [Fact]
    public void TestTwoRegMisc_FloatOneDReserved()
    {
        //fcmgt-like with sz=1, q=0 -> reserved
        Assert.Throws<Arm64UndefinedInstructionException>(() => Disassembler.DisassembleSingleInstruction(0x0E20F820U));
    }

    #endregion

    #region Advanced SIMD across lanes

    [Theory]
    [InlineData(0x0E303820U, Arm64Mnemonic.SADDLV, Arm64Register.H0, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x6E303820U, Arm64Mnemonic.UADDLV, Arm64Register.H0, Arm64ArrangementSpecifier.SixteenB)]
    [InlineData(0x0E30A820U, Arm64Mnemonic.SMAXV, Arm64Register.B0, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0E31A820U, Arm64Mnemonic.SMINV, Arm64Register.B0, Arm64ArrangementSpecifier.EightB)]
    [InlineData(0x0E31B820U, Arm64Mnemonic.ADDV, Arm64Register.B0, Arm64ArrangementSpecifier.EightB)]
    public void TestAcrossLanes_Integer(uint raw, Arm64Mnemonic mnemonic, Arm64Register dest, Arm64ArrangementSpecifier srcArr)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(dest, result.Op0Reg);
        Assert.Equal(Arm64Register.V1, result.Op1Reg);
        Assert.Equal(Arm64ArrangementSpecifier.None, result.Op0Arrangement);
        Assert.Equal(srcArr, result.Op1Arrangement);
    }

    [Theory]
    [InlineData(0x0E30C820U, Arm64Mnemonic.FMAXNMV)]
    [InlineData(0x0E30F820U, Arm64Mnemonic.FMAXV)]
    [InlineData(0x0EB0C820U, Arm64Mnemonic.FMINNMV)]
    [InlineData(0x0EB0F820U, Arm64Mnemonic.FMINV)]
    public void TestAcrossLanes_FloatHalf(uint raw, Arm64Mnemonic mnemonic)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64Register.H0, result.Op0Reg);
        Assert.Equal(Arm64ArrangementSpecifier.FourH, result.Op1Arrangement);
    }

    //Reserved near-matches: size 0b11 and unallocated opcodes must stay undefined
    [Theory]
    [InlineData(0x0E30B820U)] //opcode in the gap between xMINV and ADDV
    [InlineData(0x0E315820U)] //unallocated opcode
    public void TestAcrossLanes_Reserved(uint raw)
        => Assert.Throws<Arm64UndefinedInstructionException>(() => Disassembler.DisassembleSingleInstruction(raw));

    #endregion

    #region TBL / TBX

    [Theory]
    [InlineData(0x0E050020U, Arm64Mnemonic.TBL, Arm64ArrangementSpecifier.EightB, 1)]
    [InlineData(0x0E052020U, Arm64Mnemonic.TBL, Arm64ArrangementSpecifier.EightB, 2)]
    [InlineData(0x0E053020U, Arm64Mnemonic.TBX, Arm64ArrangementSpecifier.EightB, 2)]
    [InlineData(0x4E053020U, Arm64Mnemonic.TBX, Arm64ArrangementSpecifier.SixteenB, 2)]
    [InlineData(0x0E057020U, Arm64Mnemonic.TBX, Arm64ArrangementSpecifier.EightB, 4)]
    public void TestTableLookup(uint raw, Arm64Mnemonic mnemonic, Arm64ArrangementSpecifier destArr, int tableLength)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64Register.V0, result.Op0Reg);
        Assert.Equal(destArr, result.Op0Arrangement);
        Assert.Equal(Arm64Register.V1, result.Op1Reg);
        Assert.Equal(Arm64ArrangementSpecifier.SixteenB, result.Op1Arrangement);
        Assert.Equal(tableLength, result.Op1Imm);
        Assert.Equal(Arm64Register.V5, result.Op2Reg);
        Assert.Equal(destArr, result.Op2Arrangement);
    }

    //bit 11 set is reserved in the table lookup class
    [Fact]
    public void TestTableLookup_ReservedBit11()
        => Assert.Throws<Arm64UndefinedInstructionException>(() => Disassembler.DisassembleSingleInstruction(0x0E050820U));

    #endregion

    #region Load/store single structure (lane + replicate + post-indexed)

    [Theory]
    [InlineData(0x0D000120U, Arm64Mnemonic.ST1, Arm64VectorElementWidth.B, 0, 1)]
    [InlineData(0x0D001D20U, Arm64Mnemonic.ST1, Arm64VectorElementWidth.B, 7, 1)]
    [InlineData(0x0D002120U, Arm64Mnemonic.ST3, Arm64VectorElementWidth.B, 0, 3)]
    [InlineData(0x0D203120U, Arm64Mnemonic.ST4, Arm64VectorElementWidth.B, 4, 4)]
    [InlineData(0x4D608120U, Arm64Mnemonic.LD2, Arm64VectorElementWidth.S, 2, 2)]
    [InlineData(0x4D608520U, Arm64Mnemonic.LD2, Arm64VectorElementWidth.D, 1, 2)]
    [InlineData(0x4D60A520U, Arm64Mnemonic.LD4, Arm64VectorElementWidth.D, 1, 4)]
    public void TestSingleStructureLane(uint raw, Arm64Mnemonic mnemonic, Arm64VectorElementWidth width, int index, int regCount)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64OperandKind.VectorRegisterElement, result.Op0Kind);
        Assert.Equal(Arm64Register.V0, result.Op0Reg);
        Assert.Equal(width, result.Op0VectorElement.Width);
        Assert.Equal(index, result.Op0VectorElement.Index);
        //consecutive regs V0..V(count-1) then the memory operand
        for (var i = 1; i < regCount; i++)
        {
            var reg = i switch { 1 => result.Op1Reg, 2 => result.Op2Reg, _ => result.Op3Reg };
            Assert.Equal(Arm64Register.V0 + i, reg);
        }
    }

    [Theory]
    [InlineData(0x0D40C120U, Arm64Mnemonic.LD1R, Arm64ArrangementSpecifier.EightB, 1)]
    [InlineData(0x0D40CD20U, Arm64Mnemonic.LD1R, Arm64ArrangementSpecifier.OneD, 1)]
    [InlineData(0x0D60C120U, Arm64Mnemonic.LD2R, Arm64ArrangementSpecifier.EightB, 2)]
    [InlineData(0x4D60C520U, Arm64Mnemonic.LD2R, Arm64ArrangementSpecifier.EightH, 2)]
    [InlineData(0x0D40E120U, Arm64Mnemonic.LD3R, Arm64ArrangementSpecifier.EightB, 3)]
    [InlineData(0x4D60E120U, Arm64Mnemonic.LD4R, Arm64ArrangementSpecifier.SixteenB, 4)]
    [InlineData(0x4D60ED20U, Arm64Mnemonic.LD4R, Arm64ArrangementSpecifier.TwoD, 4)]
    public void TestSingleStructureReplicate(uint raw, Arm64Mnemonic mnemonic, Arm64ArrangementSpecifier arrangement, int regCount)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        for (var i = 0; i < regCount; i++)
        {
            var reg = i switch { 0 => result.Op0Reg, 1 => result.Op1Reg, 2 => result.Op2Reg, _ => result.Op3Reg };
            Assert.Equal(Arm64Register.V0 + i, reg);
        }
        Assert.Equal(arrangement, result.Op0Arrangement);
    }

    [Theory]
    //st1 {v0.b}[0], [x9], x5 — register post-index
    [InlineData(0x0D850120U, Arm64Mnemonic.ST1, Arm64Register.X5)]
    //ld2 {v0.s, v1.s}[2], [x9], x3 — register post-index
    [InlineData(0x4DE38120U, Arm64Mnemonic.LD2, Arm64Register.X3)]
    public void TestSingleStructurePostIndexed_Register(uint raw, Arm64Mnemonic mnemonic, Arm64Register addendReg)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64MemoryIndexMode.PostIndex, result.MemIndexMode);
        Assert.Equal(Arm64Register.X9, result.MemBase);
        Assert.Equal(addendReg, result.MemAddendReg);
    }

    [Theory]
    //st1 {v0.b}[0], [x9], #1 — immediate post-index = element size x reg count
    [InlineData(0x0D9F0120U, Arm64Mnemonic.ST1, 1)]
    //ld2 {v0.s, v1.s}[2], [x9], #8 — 2 x 4-byte s elements
    [InlineData(0x4DFF8120U, Arm64Mnemonic.LD2, 8)]
    //ld1r {v0.16b}, [x9], #1
    [InlineData(0x4DDFC120U, Arm64Mnemonic.LD1R, 1)]
    public void TestSingleStructurePostIndexed_Immediate(uint raw, Arm64Mnemonic mnemonic, long immAddend)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64MemoryIndexMode.PostIndex, result.MemIndexMode);
        Assert.Equal(Arm64Register.X9, result.MemBase);
        Assert.Equal(immAddend, result.MemOffset);
    }

    #endregion

    #region CAS / CASP / exclusive pair

    [Theory]
    [InlineData(0x08A07C20U, Arm64Mnemonic.CASB, Arm64Register.W0)]
    [InlineData(0x48A07C20U, Arm64Mnemonic.CASH, Arm64Register.W0)]
    [InlineData(0x88A07C20U, Arm64Mnemonic.CAS, Arm64Register.W0)]
    [InlineData(0xC8A07C20U, Arm64Mnemonic.CAS, Arm64Register.X0)]
    [InlineData(0xC8E07C20U, Arm64Mnemonic.CASA, Arm64Register.X0)]
    public void TestCompareAndSwap(uint raw, Arm64Mnemonic mnemonic, Arm64Register regBase)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        //cas{s} w0, w0, [x1]
        Assert.Equal(regBase, result.Op0Reg);
        Assert.Equal(regBase, result.Op1Reg);
        Assert.Equal(Arm64Register.X1, result.MemBase);
    }

    [Theory]
    //casp w0, w1, w0, w1, [x1] — Rs pair then Rt pair
    [InlineData(0x08207C20U, Arm64Mnemonic.CASP, Arm64Register.W0)]
    [InlineData(0x08607C20U, Arm64Mnemonic.CASPA, Arm64Register.W0)]
    [InlineData(0x0860FC20U, Arm64Mnemonic.CASPAL, Arm64Register.W0)]
    [InlineData(0x48207C20U, Arm64Mnemonic.CASP, Arm64Register.X0)]
    public void TestCompareAndSwapPair(uint raw, Arm64Mnemonic mnemonic, Arm64Register regBase)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(regBase, result.Op0Reg);
        Assert.Equal(regBase + 1, result.Op1Reg);
        Assert.Equal(regBase, result.Op2Reg);
        Assert.Equal(regBase + 1, result.Op3Reg);
        Assert.Equal(Arm64Register.X1, result.MemBase);
    }

    [Theory]
    //stxp w0, w0, wzr, [x1] / stlxp / ldxp / ldaxp
    [InlineData(0x88207C20U, Arm64Mnemonic.STXP)]
    [InlineData(0x8820FC20U, Arm64Mnemonic.STLXP)]
    [InlineData(0x88607C20U, Arm64Mnemonic.LDXP)]
    [InlineData(0x8860FC20U, Arm64Mnemonic.LDAXP)]
    public void TestLoadStoreExclusivePair(uint raw, Arm64Mnemonic mnemonic)
        => DisassembleAndCheckMnemonic(raw, mnemonic);

    //Compare-and-swap near-matches with reserved fields must stay undefined
    [Theory]
    [InlineData(0x08204420U)] //CASP encoding with bits 10-14 != 0b11111
    [InlineData(0x08A04420U)]
    [InlineData(0x08604420U)]
    [InlineData(0x08E04420U)]
    public void TestCompareAndSwap_Reserved(uint raw)
        => Assert.Throws<Arm64UndefinedInstructionException>(() => Disassembler.DisassembleSingleInstruction(raw));

    #endregion

    #region LSE atomics

    [Theory]
    [InlineData(0x38200020U, Arm64Mnemonic.LDADDB)]
    [InlineData(0x38202020U, Arm64Mnemonic.LDEORB)]
    [InlineData(0x38204020U, Arm64Mnemonic.LDSMAXB)]
    [InlineData(0x38206020U, Arm64Mnemonic.LDUMAXB)]
    [InlineData(0x38208020U, Arm64Mnemonic.SWPB)]
    [InlineData(0x78E00020U, Arm64Mnemonic.LDADDALH)]
    [InlineData(0xB8200020U, Arm64Mnemonic.LDADD)]
    [InlineData(0xF8200020U, Arm64Mnemonic.LDADD)]
    [InlineData(0xF8E00020U, Arm64Mnemonic.LDADDAL)]
    public void TestAtomicMemoryOperation(uint raw, Arm64Mnemonic mnemonic)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        //ldadd{b} w0, w0, [x1]
        Assert.Equal(Arm64Register.X1, result.MemBase);
    }

    //rt == 31 with a == 0 folds to the ST* store-alias form (2 operands)
    [Theory]
    [InlineData(0x3820003FU, Arm64Mnemonic.STADDB)]
    public void TestAtomicStoreAlias(uint raw, Arm64Mnemonic mnemonic)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64Register.W0, result.Op0Reg);
        Assert.Equal(Arm64Register.X1, result.MemBase);
    }

    //SWP keeps its mnemonic and three-operand form even at rt == 31
    [Fact]
    public void TestSwapToZeroRegisterKeepsOperand()
    {
        //swpb w0, wzr, [x1]
        var result = DisassembleAndCheckMnemonic(0x3820803FU, Arm64Mnemonic.SWPB);
        Assert.Equal(Arm64OperandKind.Register, result.Op1Kind);
    }

    //rt == 31 with acquire keeps the LD* mnemonic
    [Fact]
    public void TestAtomicAcquireToZeroRegister()
    {
        //ldaddab w0, wzr, [x1]
        var result = DisassembleAndCheckMnemonic(0x38A0003FU, Arm64Mnemonic.LDADDAB);
        Assert.Equal(Arm64Register.W31, result.Op1Reg);
    }

    #endregion

    #region PRFM / PRFUM

    [Theory]
    //prfm pldl1strm, [x0] / [x24, #0x220]
    [InlineData(0xF9800001U, 1, Arm64Register.X0, 0)]
    [InlineData(0xF9811270U, 0x10, Arm64Register.X19, 0x220)]
    [InlineData(0xF9804010U, 0x10, Arm64Register.X0, 0x80)]
    public void TestPrefetchUnsignedImmediate(uint raw, long prfop, Arm64Register rn, long offset)
    {
        var result = DisassembleAndCheckMnemonic(raw, Arm64Mnemonic.PRFM);
        Assert.Equal(Arm64OperandKind.Immediate, result.Op0Kind);
        Assert.Equal(prfop, result.Op0Imm);
        Assert.Equal(Arm64OperandKind.Memory, result.Op1Kind);
        Assert.Equal(rn, result.MemBase);
        Assert.Equal(offset, result.MemOffset);
    }

    [Fact]
    public void TestPrefetchUnscaled()
    {
        //prfum pldl1strm, [x19, #-0x70]
        var result = DisassembleAndCheckMnemonic(0xF8990261U, Arm64Mnemonic.PRFUM);
        Assert.Equal(1, result.Op0Imm);
        Assert.Equal(Arm64Register.X19, result.MemBase);
        Assert.Equal(-0x70, result.MemOffset);
    }

    //PRFM has no pre/post-indexed immediate forms — those encodings are reserved
    [Theory]
    [InlineData(0xF8808D21U)] //size 0b11, opc 0b10, pre-indexed — reserved
    [InlineData(0xF89F0521U)] //size 0b11, opc 0b10, post-indexed — reserved
    public void TestPrefetchPrePostReserved(uint raw)
        => Assert.Throws<Arm64UndefinedInstructionException>(() => Disassembler.DisassembleSingleInstruction(raw));

    #endregion

    #region Modified immediate MSL shift

    //movi/mvni 32-bit shifting-ones use msl, not lsl
    [Theory]
    [InlineData(0x0F00C420U, Arm64Mnemonic.MOVI)]
    [InlineData(0x2F00C420U, Arm64Mnemonic.MVNI)]
    [InlineData(0x0F00D420U, Arm64Mnemonic.MOVI)]
    public void TestModifiedImmediateMsl(uint raw, Arm64Mnemonic mnemonic)
    {
        var result = DisassembleAndCheckMnemonic(raw, mnemonic);
        Assert.Equal(Arm64ShiftType.MSL, result.Op2ShiftType);
    }

    //lsl variants unchanged
    [Theory]
    [InlineData(0x0F002420U)]
    public void TestModifiedImmediateLsl(uint raw)
    {
        var result = DisassembleAndCheckMnemonic(raw, Arm64Mnemonic.MOVI);
        Assert.Equal(Arm64ShiftType.LSL, result.Op2ShiftType);
    }

    #endregion
}
