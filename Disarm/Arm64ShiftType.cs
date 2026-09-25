namespace Disarm;

public enum Arm64ShiftType
{
    LSL, // Logical shift left
    LSR, // Logical shift right
    ASR, // Arithmetic shift right
    ROR, // Rotate right
    MSL, // Move shift left (32-bit shifting ones immediate)
    
    NONE,
}