use binaryninja::architecture;
use binaryninja::architecture::FlagRole;

use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    C,
    Z,
    N,
    V,
}

impl architecture::Flag for Flag {
    type FlagClass = Flag;

    fn name(&self) -> Cow<str> {
        match self {
            Self::C => "c".into(),
            Self::Z => "z".into(),
            Self::N => "n".into(),
            Self::V => "v".into(),
        }
    }

    fn role(&self, class: Option<Self::FlagClass>) -> architecture::FlagRole {
        match self {
            Self::C => FlagRole::CarryFlagRole,
            Self::Z => FlagRole::ZeroFlagRole,
            Self::N => FlagRole::NegativeSignFlagRole,
            Self::V => FlagRole::OverflowFlagRole,
        }
    }

    fn id(&self) -> u32 {
        match self {
            Self::C => 0,
            Self::Z => 1,
            Self::N => 2,
            Self::V => 8,
        }
    }
}

impl TryFrom<u32> for Flag {
    type Error = ();
    fn try_from(flag: u32) -> Result<Self, Self::Error> {
        match flag {
            0 => Ok(Self::C),
            1 => Ok(Self::Z),
            2 => Ok(Self::N),
            8 => Ok(Self::V),
            _ => Err(()),
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagGroup {
    None,
    All,
}

impl architecture::FlagGroup for Flag {
    type FlagType = Flag;
    type FlagClass = Flag;

    fn name(&self) -> Cow<str> {
        unimplemented!();
        /*
        match self {
            Self::None => "none".into(),
            Self::All => "all".into(),
        }
         */
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
