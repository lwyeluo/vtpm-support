
/* ACPI_EXTRACT_ALL_CODE AcpiDsdtAmlCode */

DefinitionBlock (
    "acpi-dsdt.aml",
    "DSDT",
    0x01,
    "BXPC",
    "BXDSDT",
    0x1
    )
{
Scope(\) {
    OperationRegion(DBG, SystemIO, 0x0402, 0x01)
    Field(DBG, ByteAcc, NoLock, Preserve) {
        DBGB, 8,
    }
    Method(DBUG, 1) {
        ToHexString(Arg0, Local0)
        ToBuffer(Local0, Local0)
        Subtract(SizeOf(Local0), 1, Local1)
        Store(Zero, Local2)
        While (LLess(Local2, Local1)) {
            Store(DerefOf(Index(Local0, Local2)), DBGB)
            Increment(Local2)
        }
        Store(0x0A, DBGB)
    }
}
    Scope(\_SB) {
        Device(PCI0) {
            Name(_HID, EisaId("PNP0A03"))
            Name(_ADR, 0x00)
            Name(_UID, 1)
        }
    }
Scope(\_SB) {
    Device(HPET) {
        Name(_HID, EISAID("PNP0103"))
        Name(_UID, 0)
        OperationRegion(HPTM, SystemMemory, 0xFED00000, 0x400)
        Field(HPTM, DWordAcc, Lock, Preserve) {
            VEND, 32,
            PRD, 32,
        }
        Method(_STA, 0, NotSerialized) {
            Store(VEND, Local0)
            Store(PRD, Local1)
            ShiftRight(Local0, 16, Local0)
            If (LOr(LEqual(Local0, 0), LEqual(Local0, 0xffff))) {
                Return (0x0)
            }
            If (LOr(LEqual(Local1, 0), LGreater(Local1, 100000000))) {
                Return (0x0)
            }
            Return (0x0F)
        }
        Name(_CRS, ResourceTemplate() {
            Memory32Fixed(ReadOnly,
                0xFED00000,
                0x00000400,
                )
        })
    }
}
    Scope(\_SB.PCI0) {
        Device(PX13) {
            Name(_ADR, 0x00010003)
            OperationRegion(P13C, PCI_Config, 0x00, 0xff)
        }
    }
    Scope(\_SB.PCI0) {
        External(ISA, DeviceObj)
        Device(ISA) {
            Name(_ADR, 0x00010000)
            OperationRegion(P40C, PCI_Config, 0x60, 0x04)
            Field(\_SB.PCI0.PX13.P13C, AnyAcc, NoLock, Preserve) {
                Offset(0x5f),
                , 7,
                LPEN, 1,
                Offset(0x67),
                , 3,
                CAEN, 1,
                , 3,
                CBEN, 1,
            }
            Name(FDEN, 1)
        }
    }
Scope(\_SB.PCI0.ISA) {
    Device(RTC) {
        Name(_HID, EisaId("PNP0B00"))
        Name(_CRS, ResourceTemplate() {
            IO(Decode16, 0x0070, 0x0070, 0x10, 0x02)
            IRQNoFlags() { 8 }
            IO(Decode16, 0x0072, 0x0072, 0x02, 0x06)
        })
    }
    Device(KBD) {
        Name(_HID, EisaId("PNP0303"))
        Method(_STA, 0, NotSerialized) {
            Return (0x0f)
        }
        Name(_CRS, ResourceTemplate() {
            IO(Decode16, 0x0060, 0x0060, 0x01, 0x01)
            IO(Decode16, 0x0064, 0x0064, 0x01, 0x01)
            IRQNoFlags() { 1 }
        })
    }
    Device(MOU) {
        Name(_HID, EisaId("PNP0F13"))
        Method(_STA, 0, NotSerialized) {
            Return (0x0f)
        }
        Name(_CRS, ResourceTemplate() {
            IRQNoFlags() { 12 }
        })
    }
    Device(FDC0) {
        Name(_HID, EisaId("PNP0700"))
        Method(_STA, 0, NotSerialized) {
            Store(FDEN, Local0)
            If (LEqual(Local0, 0)) {
                Return (0x00)
            } Else {
                Return (0x0F)
            }
        }
        Name(_CRS, ResourceTemplate() {
            IO(Decode16, 0x03F2, 0x03F2, 0x00, 0x04)
            IO(Decode16, 0x03F7, 0x03F7, 0x00, 0x01)
            IRQNoFlags() { 6 }
            DMA(Compatibility, NotBusMaster, Transfer8) { 2 }
        })
    }
    Device(LPT) {
        Name(_HID, EisaId("PNP0400"))
        Method(_STA, 0, NotSerialized) {
            Store(LPEN, Local0)
            If (LEqual(Local0, 0)) {
                Return (0x00)
            } Else {
                Return (0x0F)
            }
        }
        Name(_CRS, ResourceTemplate() {
            IO(Decode16, 0x0378, 0x0378, 0x08, 0x08)
            IRQNoFlags() { 7 }
        })
    }
    Device(COM1) {
        Name(_HID, EisaId("PNP0501"))
        Name(_UID, 0x01)
        Method(_STA, 0, NotSerialized) {
            Store(CAEN, Local0)
            If (LEqual(Local0, 0)) {
                Return (0x00)
            } Else {
                Return (0x0F)
            }
        }
        Name(_CRS, ResourceTemplate() {
            IO(Decode16, 0x03F8, 0x03F8, 0x00, 0x08)
            IRQNoFlags() { 4 }
        })
    }
    Device(COM2) {
        Name(_HID, EisaId("PNP0501"))
        Name(_UID, 0x02)
        Method(_STA, 0, NotSerialized) {
            Store(CBEN, Local0)
            If (LEqual(Local0, 0)) {
                Return (0x00)
            } Else {
                Return (0x0F)
            }
        }
        Name(_CRS, ResourceTemplate() {
            IO(Decode16, 0x02F8, 0x02F8, 0x00, 0x08)
            IRQNoFlags() { 3 }
        })
    }
}
    Scope(\_SB.PCI0) {
        OperationRegion(PCST, SystemIO, 0xae00, 0x08)
        Field(PCST, DWordAcc, NoLock, WriteAsZeros) {
            PCIU, 32,
            PCID, 32,
        }
        OperationRegion(SEJ, SystemIO, 0xae08, 0x04)
        Field(SEJ, DWordAcc, NoLock, WriteAsZeros) {
            B0EJ, 32,
        }
        OperationRegion(BNMR, SystemIO, 0xae10, 0x04)
        Field(BNMR, DWordAcc, NoLock, WriteAsZeros) {
            BNUM, 32,
        }
        Mutex(BLCK, 0)
        Method(PCEJ, 2, NotSerialized) {
            Acquire(BLCK, 0xFFFF)
            Store(Arg0, BNUM)
            Store(ShiftLeft(1, Arg1), B0EJ)
            Release(BLCK)
            Return (0x0)
        }
        External(\_SB.PCI0.PCNT, MethodObj)
    }
    Scope(\_SB) {
        Scope(PCI0) {
            Method (_PRT, 0) {
                Store(Package(128) {}, Local0)
                Store(Zero, Local1)
                While(LLess(Local1, 128)) {
                    Store(ShiftRight(Local1, 2), Local2)
                    Store(And(Add(Local1, Local2), 3), Local3)
                    If (LEqual(Local3, 0)) {
                        Store(Package(4) { Zero, Zero, LNKD, Zero }, Local4)
                    }
                    If (LEqual(Local3, 1)) {
                        If (LEqual(Local1, 4)) {
                            Store(Package(4) { Zero, Zero, LNKS, Zero }, Local4)
                        } Else {
                            Store(Package(4) { Zero, Zero, LNKA, Zero }, Local4)
                        }
                    }
                    If (LEqual(Local3, 2)) {
                        Store(Package(4) { Zero, Zero, LNKB, Zero }, Local4)
                    }
                    If (LEqual(Local3, 3)) {
                        Store(Package(4) { Zero, Zero, LNKC, Zero }, Local4)
                    }
                    Store(Or(ShiftLeft(Local2, 16), 0xFFFF), Index(Local4, 0))
                    Store(And(Local1, 3), Index(Local4, 1))
                    Store(Local4, Index(Local0, Local1))
                    Increment(Local1)
                }
                Return(Local0)
            }
        }
        Field(PCI0.ISA.P40C, ByteAcc, NoLock, Preserve) {
            PRQ0, 8,
            PRQ1, 8,
            PRQ2, 8,
            PRQ3, 8
        }
        Method(IQST, 1, NotSerialized) {
            If (And(0x80, Arg0)) {
                Return (0x09)
            }
            Return (0x0B)
        }
        Method(IQCR, 1, Serialized) {
            Name(PRR0, ResourceTemplate() {
                Interrupt(, Level, ActiveHigh, Shared) { 0 }
            })
            CreateDWordField(PRR0, 0x05, PRRI)
            If (LLess(Arg0, 0x80)) {
                Store(Arg0, PRRI)
            }
            Return (PRR0)
        }
        Device(LNKA) { Name(_HID, EISAID("PNP0C0F")) Name(_UID, 0) Name(_PRS, ResourceTemplate() { Interrupt(, Level, ActiveHigh, Shared) { 5, 10, 11 } }) Method(_STA, 0, NotSerialized) { Return (IQST(PRQ0)) } Method(_DIS, 0, NotSerialized) { Or(PRQ0, 0x80, PRQ0) } Method(_CRS, 0, NotSerialized) { Return (IQCR(PRQ0)) } Method(_SRS, 1, NotSerialized) { CreateDWordField(Arg0, 0x05, PRRI) Store(PRRI, PRQ0) } }
        Device(LNKB) { Name(_HID, EISAID("PNP0C0F")) Name(_UID, 1) Name(_PRS, ResourceTemplate() { Interrupt(, Level, ActiveHigh, Shared) { 5, 10, 11 } }) Method(_STA, 0, NotSerialized) { Return (IQST(PRQ1)) } Method(_DIS, 0, NotSerialized) { Or(PRQ1, 0x80, PRQ1) } Method(_CRS, 0, NotSerialized) { Return (IQCR(PRQ1)) } Method(_SRS, 1, NotSerialized) { CreateDWordField(Arg0, 0x05, PRRI) Store(PRRI, PRQ1) } }
        Device(LNKC) { Name(_HID, EISAID("PNP0C0F")) Name(_UID, 2) Name(_PRS, ResourceTemplate() { Interrupt(, Level, ActiveHigh, Shared) { 5, 10, 11 } }) Method(_STA, 0, NotSerialized) { Return (IQST(PRQ2)) } Method(_DIS, 0, NotSerialized) { Or(PRQ2, 0x80, PRQ2) } Method(_CRS, 0, NotSerialized) { Return (IQCR(PRQ2)) } Method(_SRS, 1, NotSerialized) { CreateDWordField(Arg0, 0x05, PRRI) Store(PRRI, PRQ2) } }
        Device(LNKD) { Name(_HID, EISAID("PNP0C0F")) Name(_UID, 3) Name(_PRS, ResourceTemplate() { Interrupt(, Level, ActiveHigh, Shared) { 5, 10, 11 } }) Method(_STA, 0, NotSerialized) { Return (IQST(PRQ3)) } Method(_DIS, 0, NotSerialized) { Or(PRQ3, 0x80, PRQ3) } Method(_CRS, 0, NotSerialized) { Return (IQCR(PRQ3)) } Method(_SRS, 1, NotSerialized) { CreateDWordField(Arg0, 0x05, PRRI) Store(PRRI, PRQ3) } }
        Device(LNKS) {
            Name(_HID, EISAID("PNP0C0F"))
            Name(_UID, 4)
            Name(_PRS, ResourceTemplate() {
                Interrupt(, Level, ActiveHigh, Shared) { 9 }
            })
            Method(_STA, 0, NotSerialized) { Return (0x0b) }
            Method(_DIS, 0, NotSerialized) { }
            Method(_CRS, 0, NotSerialized) { Return (_PRS) }
            Method(_SRS, 1, NotSerialized) { }
        }
    }
Scope(\_SB) {
    External(NTFY, MethodObj)
    External(CPON, PkgObj)
    External(PRS, FieldUnitObj)
    Method(CPMA, 1, NotSerialized) {
        Store(DerefOf(Index(CPON, Arg0)), Local0)
        Store(Buffer(8) {0x00, 0x08, 0x00, 0x00, 0x00, 0, 0, 0}, Local1)
        Store(Arg0, Index(Local1, 2))
        Store(Arg0, Index(Local1, 3))
        Store(Local0, Index(Local1, 4))
        Return (Local1)
    }
    Method(CPST, 1, NotSerialized) {
        Store(DerefOf(Index(CPON, Arg0)), Local0)
        If (Local0) {
            Return (0xF)
        } Else {
            Return (0x0)
        }
    }
    Method(CPEJ, 2, NotSerialized) {
        Sleep(200)
    }
    Method(PRSC, 0) {
        Store(PRS, Local5)
        Store(Zero, Local2)
        Store(Zero, Local0)
        While (LLess(Local0, SizeOf(CPON))) {
            Store(DerefOf(Index(CPON, Local0)), Local1)
            If (And(Local0, 0x07)) {
                ShiftRight(Local2, 1, Local2)
            } Else {
                Store(DerefOf(Index(Local5, ShiftRight(Local0, 3))), Local2)
            }
            Store(And(Local2, 1), Local3)
            If (LNotEqual(Local1, Local3)) {
                Store(Local3, Index(CPON, Local0))
                If (LEqual(Local3, 1)) {
                    NTFY(Local0, 1)
                } Else {
                    NTFY(Local0, 3)
                }
            }
            Increment(Local0)
        }
    }
}
    External(MTFY, MethodObj)
    Scope(\_SB.PCI0) {
        Device(MHPD) {
            Name(_HID, "PNP0A06")
            Name(_UID, "Memory hotplug resources")
            External(MDNR, IntObj)
            External(MRBL, FieldUnitObj)
            External(MRBH, FieldUnitObj)
            External(MRLL, FieldUnitObj)
            External(MRLH, FieldUnitObj)
            External(MPX, FieldUnitObj)
            External(MES, FieldUnitObj)
            External(MINS, FieldUnitObj)
            External(MRMV, FieldUnitObj)
            External(MEJ, FieldUnitObj)
            External(MSEL, FieldUnitObj)
            External(MOEV, FieldUnitObj)
            External(MOSC, FieldUnitObj)
            Method(_STA, 0) {
                If (LEqual(MDNR, Zero)) {
                    Return(0x0)
                }
                Return(0xB)
            }
            Mutex (MLCK, 0)
            Method(MSCN, 0) {
                If (LEqual(MDNR, Zero)) {
                     Return(Zero)
                }
                Store(Zero, Local0)
                Acquire(MLCK, 0xFFFF)
                while (LLess(Local0, MDNR)) {
                    Store(Local0, MSEL)
                    If (LEqual(MINS, One)) {
                        MTFY(Local0, 1)
                        Store(1, MINS)
                    } Elseif (LEqual(MRMV, One)) {
                        MTFY(Local0, 3)
                        Store(1, MRMV)
                    }
                    Add(Local0, One, Local0)
                }
                Release(MLCK)
                Return(One)
            }
            Method(MRST, 1) {
                Store(Zero, Local0)
                Acquire(MLCK, 0xFFFF)
                Store(ToInteger(Arg0), MSEL)
                If (LEqual(MES, One)) {
                    Store(0xF, Local0)
                }
                Release(MLCK)
                Return(Local0)
            }
            Method(MCRS, 1, Serialized) {
                Acquire(MLCK, 0xFFFF)
                Store(ToInteger(Arg0), MSEL)
                Name(MR64, ResourceTemplate() {
                    QWordMemory(ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    Cacheable, ReadWrite,
                    0x0000000000000000,
                    0x0000000000000000,
                    0xFFFFFFFFFFFFFFFE,
                    0x0000000000000000,
                    0xFFFFFFFFFFFFFFFF,
                    ,, MW64, AddressRangeMemory, TypeStatic)
                })
                CreateDWordField(MR64, 14, MINL)
                CreateDWordField(MR64, 18, MINH)
                CreateDWordField(MR64, 38, LENL)
                CreateDWordField(MR64, 42, LENH)
                CreateDWordField(MR64, 22, MAXL)
                CreateDWordField(MR64, 26, MAXH)
                Store(MRBH, MINH)
                Store(MRBL, MINL)
                Store(MRLH, LENH)
                Store(MRLL, LENL)
                Add(MINL, LENL, MAXL)
                Add(MINH, LENH, MAXH)
                If (LLess(MAXL, MINL)) {
                    Add(MAXH, One, MAXH)
                }
                If (LLess(MAXL, One)) {
                    Subtract(MAXH, One, MAXH)
                }
                Subtract(MAXL, One, MAXL)
                If (LEqual(MAXH, Zero)){
                    Name(MR32, ResourceTemplate() {
                        DWordMemory(ResourceProducer, PosDecode, MinFixed, MaxFixed,
                        Cacheable, ReadWrite,
                        0x00000000,
                        0x00000000,
                        0xFFFFFFFE,
                        0x00000000,
                        0xFFFFFFFF,
                        ,, MW32, AddressRangeMemory, TypeStatic)
                    })
                    CreateDWordField(MR32, MW32._MIN, MIN)
                    CreateDWordField(MR32, MW32._MAX, MAX)
                    CreateDWordField(MR32, MW32._LEN, LEN)
                    Store(MINL, MIN)
                    Store(MAXL, MAX)
                    Store(LENL, LEN)
                    Release(MLCK)
                    Return(MR32)
                }
                Release(MLCK)
                Return(MR64)
            }
            Method(MPXM, 1) {
                Acquire(MLCK, 0xFFFF)
                Store(ToInteger(Arg0), MSEL)
                Store(MPX, Local0)
                Release(MLCK)
                Return(Local0)
            }
            Method(MOST, 4) {
                Acquire(MLCK, 0xFFFF)
                Store(ToInteger(Arg0), MSEL)
                Store(Arg1, MOEV)
                Store(Arg2, MOSC)
                Release(MLCK)
            }
            Method(MEJ0, 2) {
                Acquire(MLCK, 0xFFFF)
                Store(ToInteger(Arg0), MSEL)
                Store(1, MEJ)
                Release(MLCK)
            }
        }
    }
    Scope(\_GPE) {
        Name(_HID, "ACPI0006")
        Method(_L00) {
        }
        Method(_E01) {
            Acquire(\_SB.PCI0.BLCK, 0xFFFF)
            \_SB.PCI0.PCNT()
            Release(\_SB.PCI0.BLCK)
        }
        Method(_E02) {
            \_SB.PRSC()
        }
        Method(_E03) {
            \_SB.PCI0.MHPD.MSCN()
        }
        Method(_L04) {
        }
        Method(_L05) {
        }
        Method(_L06) {
        }
        Method(_L07) {
        }
        Method(_L08) {
        }
        Method(_L09) {
        }
        Method(_L0A) {
        }
        Method(_L0B) {
        }
        Method(_L0C) {
        }
        Method(_L0D) {
        }
        Method(_L0E) {
        }
        Method(_L0F) {
        }
    }
}
