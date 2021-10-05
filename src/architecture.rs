use binaryninja::{
    architecture,
    architecture::{
        Architecture, BranchInfo, CoreArchitecture, CustomArchitectureHandle,
        InstructionInfo, InstructionTextToken, InstructionTextTokenContents, ImplicitRegisterExtend,
    },
    llil::{LiftedExpr, Lifter},
    Endianness,
};

use msp430_asm::{
    emulate::Emulated, instruction::Instruction, jxx::Jxx, operand::Operand,
    single_operand::SingleOperand, two_operand::TwoOperand,
};

use std::borrow::Cow;
use std::collections::HashMap;

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
    type FlagWrite = Flag;
    type FlagClass = Flag;
    type FlagGroup = Flag;
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
                let lifted = lift_instruction(&inst, addr, il);
                Some((inst.size(), lifted))
            },
            Err(_) => None,
        }
    }

    fn flags_required_for_flag_condition(
        &self,
        condition: architecture::FlagCondition,
        class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag> {
        Vec::new()
    }

    fn flag_group_llil<'a>(
        &self,
        group: Self::FlagGroup,
        il: &'a mut Lifter<Self>,
    ) -> Option<LiftedExpr<'a, Self>> {
        None
    }

    fn registers_all(&self) -> Vec<Self::Register> {
        (0..=15).map(|i| Register::new(i)).collect()
    }

    fn registers_full_width(&self) -> Vec<Self::Register> {
        (0..=15).map(|i| Register::new(i)).collect()
    }

    fn registers_global(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn registers_system(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn flags(&self) -> Vec<Self::Flag> {
        Vec::new()
    }

    fn flag_write_types(&self) -> Vec<Self::FlagWrite> {
        Vec::new()
    }

    fn flag_classes(&self) -> Vec<Self::FlagClass> {
        Vec::new()
    }

    fn flag_groups(&self) -> Vec<Self::FlagGroup> {
        Vec::new()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register> {
        Some(Register::new(1))
    }

    fn link_reg(&self) -> Option<Self::Register> {
        None
    }

    fn register_from_id(&self, id: u32) -> Option<Self::Register> {
        match id {
            0..=15 => Some(Register::new(id)),
            _ => None,
        }
    }

    fn flag_from_id(&self, id: u32) -> Option<Self::Flag> {
        None
    }

    fn flag_write_from_id(&self, id: u32) -> Option<Self::FlagWrite> {
        None
    }

    fn flag_class_from_id(&self, id: u32) -> Option<Self::FlagClass> {
        None
    }

    fn flag_group_from_id(&self, id: u32) -> Option<Self::FlagGroup> {
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

#[derive(Debug, Clone, Copy)]
pub struct Register {
    id: u32,
}

impl Register {
    fn new(id: u32) -> Register {
        Register { id: id }
    }
}

impl architecture::Register for Register {
    type InfoType = Self;

    fn name(&self) -> Cow<'_, str> {
        match self.id {
            0 => "pc".into(),
            1 => "sp".into(),
            2 => "sr".into(),
            3 => "cg".into(),
            4..=15 => format!("r{}", self.id).into(),
            _ => unreachable!(),
        }
    }

    fn info(&self) -> Self::InfoType {
        *self
    }

    fn id(&self) -> u32 {
        self.id
    }
}

impl architecture::RegisterInfo for Register {
    type RegType = Self;

    fn parent(&self) -> Option<Self::RegType> {
        None
    }

    fn size(&self) -> usize {
        2
    }

    fn offset(&self) -> usize {
        0
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        ImplicitRegisterExtend::NoExtend
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flag {}

impl architecture::Flag for Flag {
    type FlagClass = Flag;

    fn name(&self) -> Cow<str> {
        unimplemented!()
    }

    fn role(&self, class: Option<Self::FlagClass>) -> architecture::FlagRole {
        unimplemented!()
    }

    fn id(&self) -> u32 {
        unimplemented!()
    }
}

impl architecture::FlagClass for Flag {
    fn name(&self) -> Cow<str> {
        unimplemented!()
    }

    fn id(&self) -> u32 {
        unimplemented!()
    }
}

impl architecture::FlagGroup for Flag {
    type FlagType = Flag;
    type FlagClass = Flag;

    fn name(&self) -> Cow<str> {
        unimplemented!()
    }

    fn id(&self) -> u32 {
        unimplemented!()
    }

    fn flags_required(&self) -> Vec<Self::FlagType> {
        unimplemented!()
    }

    fn flag_conditions(&self) -> HashMap<Self, architecture::FlagCondition> {
        unimplemented!()
    }
}

impl architecture::FlagWrite for Flag {
    type FlagType = Flag;
    type FlagClass = Flag;

    fn name(&self) -> Cow<str> {
        unimplemented!()
    }

    fn class(&self) -> Option<Self::FlagClass> {
        unimplemented!()
    }

    fn id(&self) -> u32 {
        unimplemented!()
    }

    fn flags_written(&self) -> Vec<Self::FlagType> {
        unimplemented!()
    }
}

fn generate_tokens(inst: &Instruction, addr: u64) -> Vec<InstructionTextToken> {
    match inst {
        Instruction::Rrc(inst) => generate_single_operand_tokens(inst, addr),
        Instruction::Swpb(inst) => generate_single_operand_tokens(inst, addr),
        Instruction::Rra(inst) => generate_single_operand_tokens(inst, addr),
        Instruction::Sxt(inst) => generate_single_operand_tokens(inst, addr),
        Instruction::Push(inst) => generate_single_operand_tokens(inst, addr),
        Instruction::Call(inst) => generate_single_operand_tokens(inst, addr),
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

    res.extend_from_slice(&generate_operand_tokens(inst.source(), addr));

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
        InstructionTextTokenContents::PossibleAddress(fixed_addr),
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

    res.extend_from_slice(&generate_operand_tokens(inst.source(), addr));
    res.push(InstructionTextToken::new(
        InstructionTextTokenContents::OperandSeparator,
        ", ",
    ));
    res.extend_from_slice(&generate_operand_tokens(inst.destination(), addr));

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
        res.extend_from_slice(&generate_operand_tokens(&inst.destination().unwrap(), addr))
    }

    res
}

fn generate_operand_tokens(source: &Operand, addr: u64) -> Vec<InstructionTextToken> {
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
            InstructionTextTokenContents::PossibleAddress((addr as i16 + i) as u64),
            format!("{:#x}", addr as i16 + i),
        )],
        Operand::Immediate(i) => {
            vec![
                InstructionTextToken::new(InstructionTextTokenContents::Text, "#"),
                InstructionTextToken::new(
                    InstructionTextTokenContents::PossibleAddress(*i as u64),
                    format!("{:#x}", i),
                ),
            ]
        }
        Operand::Absolute(a) => vec![
            InstructionTextToken::new(InstructionTextTokenContents::Text, "&"),
            InstructionTextToken::new(
                InstructionTextTokenContents::PossibleAddress(*a as u64),
                format!("{:#x}", a),
            ),
        ],
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

fn lift_instruction(inst: &Instruction, addr: u64, il: &Lifter<Msp430>) -> bool {
    match inst {
        Instruction::Rrc(inst) => lift_single_operand(inst, addr, il),
        Instruction::Swpb(inst) => lift_single_operand(inst, addr, il),
        Instruction::Rra(inst) => lift_single_operand(inst, addr, il),
        Instruction::Sxt(inst) => lift_single_operand(inst, addr, il),
        Instruction::Push(inst) => lift_single_operand(inst, addr, il),
        Instruction::Call(inst) => lift_single_operand(inst, addr, il),
        Instruction::Reti(_) => {
            false
        },

        // Jxx instructions
        Instruction::Jnz(inst) => lift_jxx(inst, addr, il),
        Instruction::Jz(inst) => lift_jxx(inst, addr, il),
        Instruction::Jlo(inst) => lift_jxx(inst, addr, il),
        Instruction::Jc(inst) => lift_jxx(inst, addr, il),
        Instruction::Jn(inst) => lift_jxx(inst, addr, il ),
        Instruction::Jge(inst) => lift_jxx(inst, addr, il),
        Instruction::Jl(inst) => lift_jxx(inst, addr, il),
        Instruction::Jmp(inst) => lift_jxx(inst, addr, il),

        // two operand instructions
        Instruction::Mov(inst) => lift_two_operand(inst, addr, il),
        Instruction::Add(inst) => lift_two_operand(inst, addr, il),
        Instruction::Addc(inst) => lift_two_operand(inst, addr, il),
        Instruction::Subc(inst) => lift_two_operand(inst, addr, il),
        Instruction::Sub(inst) => lift_two_operand(inst, addr, il),
        Instruction::Cmp(inst) => lift_two_operand(inst, addr, il),
        Instruction::Dadd(inst) => lift_two_operand(inst, addr, il),
        Instruction::Bit(inst) => lift_two_operand(inst, addr, il),
        Instruction::Bic(inst) => lift_two_operand(inst, addr, il),
        Instruction::Bis(inst) => lift_two_operand(inst, addr, il),
        Instruction::Xor(inst) => lift_two_operand(inst, addr, il),
        Instruction::And(inst) => lift_two_operand(inst, addr, il),

        // emulated
        Instruction::Adc(inst) => lift_emulated(inst, addr, il),
        Instruction::Br(inst) => lift_emulated(inst, addr, il),
        Instruction::Clr(inst) => lift_emulated(inst, addr, il),
        Instruction::Clrc(inst) => lift_emulated(inst, addr, il),
        Instruction::Clrn(inst) => lift_emulated(inst, addr, il),
        Instruction::Clrz(inst) => lift_emulated(inst, addr, il),
        Instruction::Dadc(inst) => lift_emulated(inst, addr, il),
        Instruction::Dec(inst) => lift_emulated(inst, addr, il),
        Instruction::Decd(inst) => lift_emulated(inst, addr, il),
        Instruction::Dint(inst) => lift_emulated(inst, addr, il),
        Instruction::Eint(inst) => lift_emulated(inst, addr, il),
        Instruction::Inc(inst) => lift_emulated(inst, addr, il),
        Instruction::Incd(inst) => lift_emulated(inst, addr, il),
        Instruction::Inv(inst) => lift_emulated(inst, addr, il),
        Instruction::Nop(inst) => lift_emulated(inst, addr, il),
        Instruction::Pop(inst) => lift_emulated(inst, addr, il),
        Instruction::Ret(inst) => lift_emulated(inst, addr, il),
        Instruction::Rla(inst) => lift_emulated(inst, addr, il),
        Instruction::Rlc(inst) => lift_emulated(inst, addr, il),
        Instruction::Sbc(inst) => lift_emulated(inst, addr, il),
        Instruction::Setc(inst) => lift_emulated(inst, addr, il),
        Instruction::Setn(inst) => lift_emulated(inst, addr, il),
        Instruction::Setz(inst) => lift_emulated(inst, addr, il),
        Instruction::Tst(inst) => lift_emulated(inst, addr, il),
    }
}

fn lift_single_operand(inst: &impl SingleOperand, addr: u64, il: &Lifter<Msp430>) -> bool {
    return false
}

fn lift_jxx(inst: &impl Jxx, addr: u64, il: &Lifter<Msp430>) -> bool {
    return false
}

fn lift_two_operand(inst: &impl TwoOperand, addr: u64, il: &Lifter<Msp430>) -> bool {
    return false
}

fn lift_emulated(inst: &impl Emulated, addr: u64, il: &Lifter<Msp430>) -> bool {
    return false
}

fn offset_to_absolute(addr: u64, offset: i16) -> u64 {
    // add + 2 to addr to get past the jxx instruction which is always 2 bytes
    ((addr + 2) as i64 + ((offset * 2) as i64)) as u64
}
