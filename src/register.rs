use binaryninja::architecture;
use binaryninja::architecture::ImplicitRegisterExtend;

use std::borrow::Cow;

#[derive(Debug, Clone, Copy)]
pub struct Register {
    id: u32,
}

impl From<u32> for Register {
    fn from(id: u32) -> Self {
        Register::new(id)
    }
}

impl Register {
    pub fn new(id: u32) -> Register {
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

impl From<Register> for binaryninja::llil::Register<Register> {
    fn from(register: Register) -> Self {
        binaryninja::llil::Register::ArchReg(register)
    }
}
