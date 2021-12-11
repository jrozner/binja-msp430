use crate::flag::{Flag, FlagClass, FlagGroup, FlagWrite};
use crate::register::Register;

use binaryninja::{
    architecture::{
        Architecture, BranchInfo, CoreArchitecture, CustomArchitectureHandle, FlagCondition,
        InstructionInfo, InstructionTextToken, InstructionTextTokenContents,
    },
    llil::{Label, LiftedExpr, Lifter},
    Endianness,
};

use msp430_asm::{
    emulate::Emulated, instruction::Instruction, jxx::Jxx, operand::Operand, operand::OperandWidth,
    single_operand::SingleOperand, two_operand::TwoOperand,
};

use binaryninja::llil::{LiftedNonSSA, Mutable, NonSSA};
use log::{error, info};

const MIN_MNEMONIC: usize = 9;

pub struct Msp430 {
    handle: CoreArchitecture,
    custom_handle: CustomArchitectureHandle<Msp430>,
}

impl Msp430 {
    pub fn new(handle: CoreArchitecture, custom_handle: CustomArchitectureHandle<Msp430>) -> Self {
        Msp430 {
            handle,
            custom_handle,
        }
    }
}

impl Architecture for Msp430 {
    type Handle = CustomArchitectureHandle<Self>;
    type RegisterInfo = Register;
    type Register = Register;
    type Flag = Flag;
    type FlagWrite = FlagWrite;
    type FlagClass = FlagClass;
    type FlagGroup = FlagGroup;
    type InstructionTextContainer = Vec<InstructionTextToken>;

    fn endianness(&self) -> Endianness {
        Endianness::LittleEndian
    }

    fn address_size(&self) -> usize {
        2 // 16 bit
    }

    fn default_integer_size(&self) -> usize {
        2 // 16 bit integers
    }

    fn instruction_alignment(&self) -> usize {
        2
    }

    fn max_instr_len(&self) -> usize {
        6
    }

    fn opcode_display_len(&self) -> usize {
        self.max_instr_len()
    }

    fn associated_arch_by_addr(&self, addr: &mut u64) -> CoreArchitecture {
        self.handle
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        match msp430_asm::decode(data) {
            Ok(inst) => {
                let mut info = InstructionInfo::new(inst.size(), false);

                match inst {
                    Instruction::Jnz(inst) => {
                        info.add_branch(
                            BranchInfo::True(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                        info.add_branch(
                            BranchInfo::False(addr + inst.size() as u64),
                            Some(self.handle),
                        );
                    }
                    Instruction::Jz(inst) => {
                        info.add_branch(
                            BranchInfo::True(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                        info.add_branch(
                            BranchInfo::False(addr + inst.size() as u64),
                            Some(self.handle),
                        );
                    }
                    Instruction::Jlo(inst) => {
                        info.add_branch(
                            BranchInfo::True(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                        info.add_branch(
                            BranchInfo::False(addr + inst.size() as u64),
                            Some(self.handle),
                        );
                    }
                    Instruction::Jc(inst) => {
                        info.add_branch(
                            BranchInfo::True(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                        info.add_branch(
                            BranchInfo::False(addr + inst.size() as u64),
                            Some(self.handle),
                        );
                    }
                    Instruction::Jn(inst) => {
                        info.add_branch(
                            BranchInfo::True(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                        info.add_branch(
                            BranchInfo::False(addr + inst.size() as u64),
                            Some(self.handle),
                        );
                    }
                    Instruction::Jge(inst) => {
                        info.add_branch(
                            BranchInfo::True(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                        info.add_branch(
                            BranchInfo::False(addr + inst.size() as u64),
                            Some(self.handle),
                        );
                    }
                    Instruction::Jl(inst) => {
                        info.add_branch(
                            BranchInfo::True(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                        info.add_branch(
                            BranchInfo::False(addr + inst.size() as u64),
                            Some(self.handle),
                        );
                    }
                    Instruction::Jmp(inst) => {
                        info.add_branch(
                            BranchInfo::Unconditional(offset_to_absolute(addr, inst.offset())),
                            Some(self.handle),
                        );
                    }
                    Instruction::Br(inst) => match inst.destination() {
                        Some(Operand::Immediate(addr)) => info
                            .add_branch(BranchInfo::Unconditional(*addr as u64), Some(self.handle)),
                        _ => {}
                    },
                    Instruction::Call(inst) => match inst.source() {
                        Operand::Immediate(addr) => {
                            info.add_branch(BranchInfo::Call(*addr as u64), Some(self.handle));
                        }
                        _ => {}
                    },
                    Instruction::Reti(_) => {
                        info.add_branch(BranchInfo::FunctionReturn, Some(self.handle));
                    }
                    Instruction::Ret(_) => {
                        info.add_branch(BranchInfo::FunctionReturn, Some(self.handle));
                    }
                    _ => {}
                }

                Some(info)
            }
            Err(_) => None,
        }
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Self::InstructionTextContainer)> {
        match msp430_asm::decode(data) {
            Ok(inst) => {
                let tokens = generate_tokens(&inst, addr);
                if tokens.len() < 1 {
                    None
                } else {
                    Some((inst.size(), tokens))
                }
            }
            Err(_) => None,
        }
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut Lifter<Self>,
    ) -> Option<(usize, bool)> {
        match msp430_asm::decode(data) {
            Ok(inst) => {
                lift_instruction(&inst, addr, il);
                Some((inst.size(), true))
            }
            Err(_) => None,
        }
    }

    fn flags_required_for_flag_condition(
        &self,
        condition: FlagCondition,
        class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag> {
        match condition {
            FlagCondition::LLFC_UGE => vec![Flag::C],
            FlagCondition::LLFC_ULT => vec![Flag::C],
            FlagCondition::LLFC_SGE => vec![Flag::N, Flag::V],
            FlagCondition::LLFC_SLT => vec![Flag::N, Flag::V],
            FlagCondition::LLFC_E => vec![Flag::Z],
            FlagCondition::LLFC_NE => vec![Flag::Z],
            FlagCondition::LLFC_NEG => vec![Flag::N],
            FlagCondition::LLFC_POS => vec![Flag::N],
            _ => vec![],
        }
    }

    fn flag_group_llil<'a>(
        &self,
        group: Self::FlagGroup,
        il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn registers_all(&self) -> Vec<Self::Register> {
        vec![
            Register::Pc,
            Register::Sp,
            Register::Sr,
            Register::Cg,
            Register::R4,
            Register::R5,
            Register::R6,
            Register::R7,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ]
    }

    fn registers_full_width(&self) -> Vec<Self::Register> {
        vec![
            Register::Pc,
            Register::Sp,
            Register::Sr,
            Register::Cg,
            Register::R4,
            Register::R5,
            Register::R6,
            Register::R7,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ]
    }

    fn registers_global(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn registers_system(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn flags(&self) -> Vec<Self::Flag> {
        vec![Flag::C, Flag::Z, Flag::N, Flag::V]
    }

    fn flag_write_types(&self) -> Vec<Self::FlagWrite> {
        vec![FlagWrite::All, FlagWrite::Cnz]
    }

    fn flag_classes(&self) -> Vec<Self::FlagClass> {
        Vec::new()
    }

    fn flag_groups(&self) -> Vec<Self::FlagGroup> {
        Vec::new()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register> {
        Some(Register::Sp)
    }

    fn link_reg(&self) -> Option<Self::Register> {
        None
    }

    fn register_from_id(&self, id: u32) -> Option<Self::Register> {
        match id.try_into() {
            Ok(register) => Some(register),
            Err(_) => {
                error!("invalid register id {}", id);
                None
            }
        }
    }

    fn flag_from_id(&self, id: u32) -> Option<Self::Flag> {
        match id.try_into() {
            Ok(flag) => Some(flag),
            Err(_) => {
                error!("invalid flag id {}", id);
                None
            }
        }
    }

    fn flag_write_from_id(&self, id: u32) -> Option<Self::FlagWrite> {
        match id.try_into() {
            Ok(flag_write) => Some(flag_write),
            Err(_) => {
                error!("invalid flag write id {}", id);
                None
            }
        }
    }

    fn flag_class_from_id(&self, _: u32) -> Option<Self::FlagClass> {
        None
    }

    fn flag_group_from_id(&self, _: u32) -> Option<Self::FlagGroup> {
        None
    }

    fn handle(&self) -> Self::Handle {
        self.custom_handle
    }
}

impl AsRef<CoreArchitecture> for Msp430 {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.handle
    }
}

fn generate_tokens(inst: &Instruction, addr: u64) -> Vec<InstructionTextToken> {
    match inst {
        Instruction::Rrc(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Swpb(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Rra(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Sxt(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Push(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Call(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Reti(_) => vec![InstructionTextToken::new(
            InstructionTextTokenContents::Instruction,
            format!("{}", "reti"),
        )],

        // Jxx instructions
        Instruction::Jnz(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jz(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jlo(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jc(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jn(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jge(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jl(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jmp(inst) => generate_jxx_tokens(inst, addr),

        // two operand instructions
        Instruction::Mov(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Add(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Addc(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Subc(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Sub(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Cmp(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Dadd(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Bit(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Bic(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Bis(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Xor(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::And(inst) => generate_two_operand_tokens(inst, addr),

        // emulated
        Instruction::Adc(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Br(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Clr(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Clrc(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Clrn(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Clrz(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Dadc(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Dec(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Decd(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Dint(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Eint(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Inc(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Incd(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Inv(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Nop(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Pop(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Ret(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Rla(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Rlc(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Sbc(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Setc(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Setn(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Setz(inst) => generate_emulated_tokens(inst, addr),
        Instruction::Tst(inst) => generate_emulated_tokens(inst, addr),
    }
}

fn generate_single_operand_tokens(
    inst: &impl SingleOperand,
    addr: u64,
    call: bool,
) -> Vec<InstructionTextToken> {
    let mut res = vec![InstructionTextToken::new(
        InstructionTextTokenContents::Instruction,
        format!("{}", inst.mnemonic()),
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = std::iter::repeat(" ")
            .take(MIN_MNEMONIC - inst.mnemonic().len())
            .collect::<String>();
        res.push(InstructionTextToken::new(
            InstructionTextTokenContents::Text,
            padding,
        ))
    }

    res.extend_from_slice(&generate_operand_tokens(inst.source(), addr, call));

    res
}

fn generate_jxx_tokens(inst: &impl Jxx, addr: u64) -> Vec<InstructionTextToken> {
    let fixed_addr = offset_to_absolute(addr, inst.offset());

    let mut res = vec![InstructionTextToken::new(
        InstructionTextTokenContents::Instruction,
        format!("{}", inst.mnemonic()),
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = std::iter::repeat(" ")
            .take(MIN_MNEMONIC - inst.mnemonic().len())
            .collect::<String>();
        res.push(InstructionTextToken::new(
            InstructionTextTokenContents::Text,
            padding,
        ))
    }

    res.push(InstructionTextToken::new(
        InstructionTextTokenContents::CodeRelativeAddress(fixed_addr),
        format!("0x{:4x}", fixed_addr),
    ));

    res
}

fn generate_two_operand_tokens(inst: &impl TwoOperand, addr: u64) -> Vec<InstructionTextToken> {
    let mut res = vec![InstructionTextToken::new(
        InstructionTextTokenContents::Instruction,
        format!("{}", inst.mnemonic()),
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = std::iter::repeat(" ")
            .take(MIN_MNEMONIC - inst.mnemonic().len())
            .collect::<String>();
        res.push(InstructionTextToken::new(
            InstructionTextTokenContents::Text,
            padding,
        ))
    }

    res.extend_from_slice(&generate_operand_tokens(inst.source(), addr, false));
    res.push(InstructionTextToken::new(
        InstructionTextTokenContents::OperandSeparator,
        ", ",
    ));
    res.extend_from_slice(&generate_operand_tokens(inst.destination(), addr, false));

    res
}

fn generate_emulated_tokens(inst: &impl Emulated, addr: u64) -> Vec<InstructionTextToken> {
    let mut res = vec![InstructionTextToken::new(
        InstructionTextTokenContents::Instruction,
        format!("{}", inst.mnemonic()),
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = std::iter::repeat(" ")
            .take(MIN_MNEMONIC - inst.mnemonic().len())
            .collect::<String>();
        res.push(InstructionTextToken::new(
            InstructionTextTokenContents::Text,
            padding,
        ))
    }

    if inst.destination().is_some() {
        res.extend_from_slice(&generate_operand_tokens(
            &inst.destination().unwrap(),
            addr,
            false,
        ))
    }

    res
}

fn generate_operand_tokens(source: &Operand, addr: u64, call: bool) -> Vec<InstructionTextToken> {
    match source {
        Operand::RegisterDirect(r) => match r {
            0 => vec![InstructionTextToken::new(
                InstructionTextTokenContents::Register,
                "pc",
            )],
            1 => vec![InstructionTextToken::new(
                InstructionTextTokenContents::Register,
                "sp",
            )],
            2 => vec![InstructionTextToken::new(
                InstructionTextTokenContents::Register,
                "sr",
            )],
            3 => vec![InstructionTextToken::new(
                InstructionTextTokenContents::Register,
                "cg",
            )],
            _ => vec![InstructionTextToken::new(
                InstructionTextTokenContents::Register,
                format!("r{}", r),
            )],
        },
        Operand::Indexed((r, i)) => match r {
            0 => {
                let num_text = if *i >= 0 {
                    format!("{:#x}", i)
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        InstructionTextTokenContents::Integer(*i as u64),
                        num_text,
                    ),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, "("),
                    InstructionTextToken::new(InstructionTextTokenContents::Register, "pc"),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, ")"),
                ]
            }
            1 => {
                let num_text = if *i >= 0 {
                    format!("{:#x}", i)
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        InstructionTextTokenContents::Integer(*i as u64),
                        num_text,
                    ),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, "("),
                    InstructionTextToken::new(InstructionTextTokenContents::Register, "sp"),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, ")"),
                ]
            }
            2 => {
                let num_text = if *i >= 0 {
                    format!("{:#x}", i)
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        InstructionTextTokenContents::Integer(*i as u64),
                        num_text,
                    ),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, "("),
                    InstructionTextToken::new(InstructionTextTokenContents::Register, "sr"),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, ")"),
                ]
            }
            3 => {
                let num_text = if *i >= 0 {
                    format!("{:#x}", i)
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        InstructionTextTokenContents::Integer(*i as u64),
                        num_text,
                    ),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, "("),
                    InstructionTextToken::new(InstructionTextTokenContents::Register, "cg"),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, ")"),
                ]
            }
            _ => {
                let num_text = if *i >= 0 {
                    format!("{:#x}", i)
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        InstructionTextTokenContents::Integer(*i as u64),
                        num_text,
                    ),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, "("),
                    InstructionTextToken::new(
                        InstructionTextTokenContents::Register,
                        format!("r{}", r),
                    ),
                    InstructionTextToken::new(InstructionTextTokenContents::Text, ")"),
                ]
            }
        },
        Operand::RegisterIndirect(r) => {
            let r_text = if *r == 1 {
                "sp".into()
            } else {
                format!("r{}", r)
            };

            vec![
                InstructionTextToken::new(InstructionTextTokenContents::Text, "@"),
                InstructionTextToken::new(InstructionTextTokenContents::Register, r_text),
            ]
        }
        Operand::RegisterIndirectAutoIncrement(r) => {
            let r_text = if *r == 1 {
                "sp".into()
            } else {
                format!("r{}", r)
            };

            vec![
                InstructionTextToken::new(InstructionTextTokenContents::Text, "@"),
                InstructionTextToken::new(InstructionTextTokenContents::Register, r_text),
                InstructionTextToken::new(InstructionTextTokenContents::Text, "+"),
            ]
        }
        // TODO: is this correct? can you know what this is without knowing what PC is?
        Operand::Symbolic(i) => vec![InstructionTextToken::new(
            InstructionTextTokenContents::CodeRelativeAddress((addr as i16 + i) as u64),
            format!("{:#x}", addr as i16 + i),
        )],
        Operand::Immediate(i) => {
            if call {
                vec![InstructionTextToken::new(
                    InstructionTextTokenContents::CodeRelativeAddress(*i as u64),
                    format!("{:#x}", i),
                )]
            } else {
                vec![InstructionTextToken::new(
                    InstructionTextTokenContents::PossibleAddress(*i as u64),
                    format!("{:#x}", i),
                )]
            }
        }
        Operand::Absolute(a) => {
            if call {
                vec![InstructionTextToken::new(
                    InstructionTextTokenContents::CodeRelativeAddress(*a as u64),
                    format!("{:#x}", a),
                )]
            } else {
                vec![InstructionTextToken::new(
                    InstructionTextTokenContents::PossibleAddress(*a as u64),
                    format!("{:#x}", a),
                )]
            }
        }
        Operand::Constant(i) => {
            let num_text = if *i >= 0 {
                format!("{:#x}", i)
            } else {
                format!("-{:#x}", -i)
            };

            vec![
                InstructionTextToken::new(InstructionTextTokenContents::Text, "#"),
                InstructionTextToken::new(
                    InstructionTextTokenContents::Integer(*i as u64),
                    num_text,
                ),
            ]
        }
    }
}

macro_rules! auto_increment {
    ($src:expr, $il:ident) => {
        if let Operand::RegisterIndirectAutoIncrement(r) = $src {
            $il.set_reg(
                2,
                Register::try_from(*r as u32).unwrap(),
                $il.add(
                    2,
                    $il.reg(2, Register::try_from(*r as u32).unwrap()),
                    $il.const_int(2, 2),
                ),
            )
            .append();
        }
    };
}

macro_rules! two_operand {
    ($inst:ident, $il:ident, $op:ident) => {
        match $inst.destination() {
            Operand::RegisterDirect(r) => $il
                .set_reg(2, Register::try_from(*r as u32).unwrap(), $op)
                .append(),
            Operand::Indexed((r, offset)) => $il
                .store(
                    2,
                    $il.add(
                        2,
                        $il.reg(2, Register::try_from(*r as u32).unwrap()),
                        $il.const_int(2, *offset as u64),
                    ),
                    $op,
                )
                .append(),
            Operand::Symbolic(offset) => $il
                .store(2, $il.add(2, $il.reg(2, Register::Pc), *offset as u64), $op)
                .append(),
            Operand::Absolute(val) => $il.store(2, $il.const_ptr(*val as u64), $op).append(),
            _ => {
                unreachable!()
            }
        };
    };
}

macro_rules! emulated {
    ($inst:ident, $il:ident, $op:ident) => {
        match $inst.destination() {
            Some(Operand::RegisterDirect(r)) => $il
                .set_reg(2, Register::try_from(*r as u32).unwrap(), $op)
                .append(),
            Some(Operand::Indexed((r, offset))) => $il
                .store(
                    2,
                    $il.add(
                        2,
                        $il.reg(2, Register::try_from(*r as u32).unwrap()),
                        $il.const_int(2, *offset as u64),
                    ),
                    $op,
                )
                .append(),
            Some(Operand::Symbolic(offset)) => $il
                .store(2, $il.add(2, $il.reg(2, Register::Pc), *offset as u64), $op)
                .append(),
            Some(Operand::Absolute(val)) => $il.store(2, $il.const_ptr(*val as u64), $op).append(),
            _ => {
                unreachable!()
            }
        };
    };
}

macro_rules! conditional_jump {
    ($addr:ident, $inst:ident, $cond:ident, $il:ident) => {
        let true_addr = offset_to_absolute($addr, $inst.offset());
        let false_addr = $addr + $inst.size() as u64;
        let mut new_true = Label::new();
        let mut new_false = Label::new();

        let true_label = $il.label_for_address(true_addr);
        let false_label = $il.label_for_address(false_addr);

        $il.if_expr(
            $cond,
            true_label.unwrap_or_else(|| &new_true),
            false_label.unwrap_or_else(|| &new_false),
        )
        .append();

        if true_label.is_none() {
            $il.mark_label(&mut new_true);
        }

        $il.goto(true_label.unwrap_or_else(|| &new_true)).append();

        if false_label.is_none() {
            $il.mark_label(&mut new_false);
        }
    };
}

fn lift_instruction(inst: &Instruction, addr: u64, il: &Lifter<Msp430>) {
    match inst {
        Instruction::Rrc(_) => {
            il.unimplemented().append();
        }
        Instruction::Swpb(_) => {
            il.unimplemented().append();
        }
        Instruction::Rra(_) => {
            il.unimplemented().append();
        }
        Instruction::Sxt(_) => {
            il.unimplemented().append();
        }
        Instruction::Push(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            il.push(2, src).append();
            auto_increment!(inst.source(), il);
        }
        Instruction::Call(inst) => {
            // TODO: if immediate mode need to make argument CONST_PTR rather than CONST_INT
            // TODO: verify the special autoincrement behavior Josh implemented?
            let src = lift_source_operand(inst.source(), addr, il);
            il.call(src).append();
            auto_increment!(inst.source(), il);
        }
        Instruction::Reti(_) => {
            il.set_reg(2, Register::Sr, il.pop(2))
                .with_flag_write(FlagWrite::All)
                .append();
            il.ret(il.pop(2)).append();
        }

        // Jxx instructions
        Instruction::Jnz(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_NE);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jz(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_E);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jlo(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_ULT);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jc(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_UGE);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jn(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_NEG);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jge(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_SGE);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jl(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_SLT);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jmp(inst) => {
            let fixed_addr = offset_to_absolute(addr, inst.offset());
            let label = il.label_for_address(fixed_addr);
            match label {
                Some(label) => {
                    il.goto(label).append();
                }
                None => {
                    il.jump(il.const_ptr(fixed_addr)).append();
                }
            }
        }

        // two operand instructions
        Instruction::Mov(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            two_operand!(inst, il, src);
            auto_increment!(inst.source(), il);
        }
        Instruction::Add(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il.add(2, src, dest).with_flag_write(FlagWrite::All);
            two_operand!(inst, il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Addc(inst) => {
            il.unimplemented().append();
        }
        Instruction::Subc(inst) => {
            il.unimplemented().append();
        }
        Instruction::Sub(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il.sub(2, src, dest).with_flag_write(FlagWrite::All);
            two_operand!(inst, il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Cmp(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il
                .sub(2, dest, src)
                .with_flag_write(FlagWrite::All)
                .append();
            auto_increment!(inst.source(), il);
        }
        Instruction::Dadd(inst) => {
            il.unimplemented().append();
        }
        Instruction::Bit(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il.and(2, src, dest);
            two_operand!(inst, il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Bic(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il.and(2, il.not(2, src), dest);
            two_operand!(inst, il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Bis(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il.or(2, src, dest);
            two_operand!(inst, il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Xor(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il.xor(2, src, dest);
            two_operand!(inst, il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::And(inst) => {
            let src = lift_source_operand(inst.source(), addr, il);
            let dest = lift_source_operand(inst.destination(), addr, il);
            let op = il.and(2, src, dest);
            two_operand!(inst, il, op);
            auto_increment!(inst.source(), il);
        }

        // emulated
        Instruction::Adc(_) => {
            il.unimplemented().append();
        }
        Instruction::Br(_) => {
            il.unimplemented().append();
        }
        Instruction::Clr(inst) => {
            let op = il.const_int(2, 0);
            emulated!(inst, il, op);
        }
        Instruction::Clrc(_) => {
            il.set_flag(Flag::C, il.const_int(0, 1)).append();
        }
        Instruction::Clrn(_) => {
            il.set_flag(Flag::N, il.const_int(0, 1)).append();
        }
        Instruction::Clrz(_) => {
            il.set_flag(Flag::Z, il.const_int(0, 1)).append();
        }
        Instruction::Dadc(_) => {
            il.unimplemented().append();
        }
        Instruction::Dec(inst) => {
            let dest = lift_source_operand(&inst.destination().unwrap(), addr, il);
            let op = il
                .sub(2, dest, il.const_int(2, 1))
                .with_flag_write(FlagWrite::All);
            emulated!(inst, il, op);
        }
        Instruction::Decd(inst) => {
            let dest = lift_source_operand(&inst.destination().unwrap(), addr, il);
            let op = il
                .sub(2, dest, il.const_int(2, 2))
                .with_flag_write(FlagWrite::All);
            emulated!(inst, il, op);
        }
        Instruction::Dint(_) => {
            // NOTE: Lifting would probably just clear the GIE (flag) but likely doesn't have any other meaningful impact
            il.unimplemented().append();
        }
        Instruction::Eint(_) => {
            // NOTE: Lifting would probably just set the GIE (flag) but likely doesn't have any other meaningful impact
            il.unimplemented().append();
        }
        Instruction::Inc(inst) => {
            let dest = lift_source_operand(&inst.destination().unwrap(), addr, il);
            let op = il
                .add(2, dest, il.const_int(2, 1))
                .with_flag_write(FlagWrite::All);
            emulated!(inst, il, op);
        }
        Instruction::Incd(inst) => {
            let dest = lift_source_operand(&inst.destination().unwrap(), addr, il);
            let op = il
                .add(2, dest, il.const_int(2, 2))
                .with_flag_write(FlagWrite::All);
            emulated!(inst, il, op);
        }
        Instruction::Inv(inst) => {
            let dest = lift_source_operand(&inst.destination().unwrap(), addr, il);
            let op = il
                .not(2, dest)
                .with_flag_write(FlagWrite::All);
            emulated!(inst, il, op);
        }
        Instruction::Nop(_) => {
            il.nop().append();
        }
        Instruction::Pop(inst) => {
            if let Some(Operand::RegisterDirect(r)) = inst.destination() {
                il.set_reg(2, Register::try_from(*r as u32).unwrap(), il.pop(2))
                    .append();
            } else {
                info!("pop: invalid destination operand");
            }
        }
        Instruction::Ret(_) => {
            il.ret(il.pop(2)).append();
        }
        Instruction::Rla(_) => {
            il.unimplemented().append();
        }
        Instruction::Rlc(_) => {
            il.unimplemented().append();
        }
        Instruction::Sbc(_) => {
            il.unimplemented().append();
        }
        Instruction::Setc(_) => {
            il.set_flag(Flag::C, il.const_int(0, 1)).append();
        }
        Instruction::Setn(_) => {
            il.set_flag(Flag::N, il.const_int(0, 1)).append();
        }
        Instruction::Setz(_) => {
            il.set_flag(Flag::Z, il.const_int(0, 1)).append();
        }
        Instruction::Tst(inst) => {
            let dest = lift_source_operand(&inst.destination().unwrap(), addr, il);
            il.sub(2, dest, il.const_int(2, 0))
                .with_flag_write(FlagWrite::All)
                .append();
        }
    }
}

fn lift_source_operand<'a>(
    operand: &Operand,
    addr: u64,
    il: &'a Lifter<Msp430>,
) -> binaryninja::llil::Expression<
    'a,
    Msp430,
    Mutable,
    NonSSA<LiftedNonSSA>,
    binaryninja::llil::ValueExpr,
> {
    match operand {
        Operand::RegisterDirect(r) => il.reg(2, Register::try_from(*r as u32).unwrap()),
        Operand::Indexed((r, offset)) => il
            .load(
                2,
                il.add(
                    2,
                    il.reg(2, Register::try_from(*r as u32).unwrap()),
                    il.const_int(2, *offset as u64),
                ),
            )
            .into_expr(),
        // should we add offset to addr here rather than lifting to the register since we know where PC is?
        Operand::Symbolic(offset) => il
            .load(
                2,
                il.add(2, il.reg(2, Register::Pc), il.const_int(2, *offset as u64)),
            )
            .into_expr(),
        Operand::Absolute(addr) => il.load(2, il.const_ptr(*addr as u64)).into_expr(),
        // these are the same, we need to autoincrement in a separate il instruction
        Operand::RegisterIndirect(r) | Operand::RegisterIndirectAutoIncrement(r) => il
            .load(2, il.reg(2, Register::try_from(*r as u32).unwrap()))
            .into_expr(),
        Operand::Immediate(val) => il.const_int(2, *val as u64),
        Operand::Constant(val) => il.const_int(2, *val as u64),
    }
}

fn width_to_size(width: &OperandWidth) -> usize {
    match width {
        OperandWidth::Byte => 1,
        OperandWidth::Word => 2,
    }
}

fn offset_to_absolute(addr: u64, offset: i16) -> u64 {
    // add + 2 to addr to get past the jxx instruction which is always 2 bytes
    ((addr + 2) as i64 + ((offset * 2) as i64)) as u64
}
