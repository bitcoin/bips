
use bitcoin::{Transaction, TxOut};
use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};

pub const TXFS_VERSION: u8 = 1 << 0;
pub const TXFS_LOCKTIME: u8 = 1 << 1;
pub const TXFS_CURRENT_INPUT_IDX: u8 = 1 << 2;
pub const TXFS_CURRENT_INPUT_SPENTSCRIPT: u8 = 1 << 3;
pub const TXFS_CURRENT_INPUT_CONTROL_BLOCK: u8 = 1 << 4;
pub const TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS: u8 = 1 << 5;
// pub const TXFS_UNUSED: u8 = 1 << 6;
pub const TXFS_CONTROL: u8 = 1 << 7;

pub const TXFS_ALL: u8 = TXFS_VERSION
    | TXFS_LOCKTIME
    | TXFS_CURRENT_INPUT_IDX
    | TXFS_CURRENT_INPUT_SPENTSCRIPT
    | TXFS_CURRENT_INPUT_CONTROL_BLOCK
    | TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS
    | TXFS_CONTROL;

pub const TXFS_INPUTS_PREVOUTS: u8 = 1 << 0;
pub const TXFS_INPUTS_SEQUENCES: u8 = 1 << 1;
pub const TXFS_INPUTS_SCRIPTSIGS: u8 = 1 << 2;
pub const TXFS_INPUTS_PREV_SCRIPTPUBKEYS: u8 = 1 << 3;
pub const TXFS_INPUTS_PREV_VALUES: u8 = 1 << 4;
pub const TXFS_INPUTS_TAPROOT_ANNEXES: u8 = 1 << 5;
pub const TXFS_OUTPUTS_SCRIPTPUBKEYS: u8 = 1 << 6;
pub const TXFS_OUTPUTS_VALUES: u8 = 1 << 7;

pub const TXFS_INPUTS_ALL: u8 = TXFS_INPUTS_PREVOUTS
    | TXFS_INPUTS_SEQUENCES
    | TXFS_INPUTS_SCRIPTSIGS
    | TXFS_INPUTS_PREV_SCRIPTPUBKEYS
    | TXFS_INPUTS_PREV_VALUES
    | TXFS_INPUTS_TAPROOT_ANNEXES;
pub const TXFS_INPUTS_TEMPLATE: u8 = TXFS_INPUTS_SEQUENCES
    | TXFS_INPUTS_SCRIPTSIGS
    | TXFS_INPUTS_PREV_VALUES
    | TXFS_INPUTS_TAPROOT_ANNEXES;
pub const TXFS_OUTPUTS_ALL: u8 = TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES;

pub const TXFS_INOUT_NUMBER: u8 = 1 << 7;
pub const TXFS_INOUT_SELECTION_NONE: u8 = 0x00;
pub const TXFS_INOUT_SELECTION_CURRENT: u8 = 0x40;
pub const TXFS_INOUT_SELECTION_ALL: u8 = 0x3f;
pub const TXFS_INOUT_SELECTION_MODE: u8 = 1 << 6;
pub const TXFS_INOUT_LEADING_SIZE: u8 = 1 << 5;
pub const TXFS_INOUT_INDIVIDUAL_MODE: u8 = 1 << 5;
pub const TXFS_INOUT_SELECTION_MASK: u8 = 0xff ^ (1 << 7) ^ (1 << 6) ^ (1 << 5);


pub const TXFS_SPECIAL_ALL: [u8; 4] = [
    TXFS_ALL,
    TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
];
pub const TXFS_SPECIAL_TEMPLATE: [u8; 4] = [
    TXFS_ALL,
    TXFS_INPUTS_TEMPLATE | TXFS_OUTPUTS_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
];

const SHA256_EMPTY: sha256::Hash = sha256::Hash::const_hash(&[]);

fn read_i7(input: u8) -> i8 {
    let masked = input & 0x7f;
    if (masked & 0x40) == 0 {
        masked as i8
    } else {
        0i8 - ((!(masked-1)) & 0x7f) as i8
    }
}

fn read_i15(input: u16) -> i16 {
    let masked = input & 0x7fff;
    if (masked & 0x4000) == 0 {
        masked as i16
    } else {
        0i16 - ((!(masked-1)) & 0x7fff) as i16
    }
}

/// Parse an input or output selection from the TxFieldSelector bytes.
///
/// Returns the selected indices and a flag whether to commit the number of items.
fn parse_inout_selection(
    bytes: &mut impl Iterator<Item = u8>,
    nb_items: usize,
    current_input_idx: u32,
    allow_empty: bool,
) -> Result<(Vec<usize>, bool), &'static str> {
    let first = match bytes.next() {
        Some(b) => b,
        None if !allow_empty => return Ok((vec![], false)),
        None /* if allow_empty */ => return Err("byte missing instead of empty selection"),
    };
    let commit_number = (first & TXFS_INOUT_NUMBER) != 0;
    let selection = first & (0xff ^ TXFS_INOUT_NUMBER);

    let selected = if selection == TXFS_INOUT_SELECTION_NONE {
        vec![]
    } else if selection == TXFS_INOUT_SELECTION_ALL {
        (0..nb_items).collect()
    } else if selection == TXFS_INOUT_SELECTION_CURRENT {
        if current_input_idx as usize >= nb_items {
            // NB can only happen for outputs
            return Err("current input index exceeds number of outputs and current output selected");
        }
        vec![current_input_idx as usize]
    } else if (selection & TXFS_INOUT_SELECTION_MODE) == 0 { // leading mode
        let count = if (selection & TXFS_INOUT_LEADING_SIZE) == 0 {
            (selection & TXFS_INOUT_SELECTION_MASK) as usize
        } else {
            let next_byte = bytes.next().ok_or("second leading selection byte missing")?;
            (((selection & TXFS_INOUT_SELECTION_MASK) as usize) << 8) + next_byte as usize
        };
        assert_ne!(count, 0, "this should be interpreted as NONE above");
        if count > nb_items {
            return Err("selected number of leading in/outputs out of bounds");
        }
        (0..count).collect()
    } else { // individual mode
        let absolute = (selection & TXFS_INOUT_INDIVIDUAL_MODE) == 0;

        let count = (selection & TXFS_INOUT_SELECTION_MASK) as usize;

        let mut selected = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let first = bytes.next().ok_or("expected an index byte")?;
            let single_byte = (first & (1 << 7)) == 0;
            let number = if single_byte {
                first as usize
            } else {
                let next_byte = bytes.next().ok_or("expected another index byte")?;
                (((first & (1 << 7)) as usize) << 8) + next_byte as usize
            };

            let idx = if absolute {
                number
            } else {
                let rel = if single_byte {
                    read_i7(number as u8) as isize
                } else {
                    read_i15(number as u16) as isize
                };

                if rel.is_negative() && rel.abs() > current_input_idx as isize {
                    return Err("relative index out of bounds");
                }
                (current_input_idx as isize + rel) as usize
            };

            if idx > nb_items {
                return Err("selected index out of bounds");
            }
            if let Some(last) = selected.last() {
                if idx <= *last {
                    return Err("selected indices not in increasing order")
                }
            }
            selected.push(idx);
        }
        selected
    };
    Ok((selected, commit_number))
}

/// 
///
/// Assumes that TxFieldSelector is valid.
pub fn calculate_txhash(
    txfs: &[u8],
    tx: &Transaction,
    prevouts: &[TxOut],
    current_input_idx: u32,
    current_input_last_codeseparator_pos: Option<u32>,
) -> Result<sha256::Hash, &'static str> {
    assert_eq!(tx.input.len(), prevouts.len());

    let txfs = if txfs.is_empty() {
        &TXFS_SPECIAL_TEMPLATE
    } else if txfs.len() == 1 && txfs[0] == 0x00 {
        &TXFS_SPECIAL_ALL
    } else {
        txfs
    };

    let mut engine = sha256::Hash::engine();

    if (txfs[0] & TXFS_CONTROL) != 0 {
        engine.input(txfs);
    }

    let mut bytes = txfs.iter().copied().peekable();
    let global = bytes.next().unwrap();

    if (global & TXFS_VERSION) != 0 {
        tx.version.consensus_encode(&mut engine).unwrap();
    }

    if (global & TXFS_LOCKTIME) != 0 {
        tx.lock_time.consensus_encode(&mut engine).unwrap();
    }

    if (global & TXFS_CURRENT_INPUT_IDX) != 0 {
        (current_input_idx as u32).consensus_encode(&mut engine).unwrap();
    }

    let cur = current_input_idx as usize;
    if (global & TXFS_CURRENT_INPUT_SPENTSCRIPT) != 0 {
        let ss = if prevouts[cur].script_pubkey.is_p2sh() {
            tx.input[cur].script_sig.redeem_script().map(|s| s.as_bytes()).unwrap_or(&[])
        } else if prevouts[cur].script_pubkey.is_p2wsh() {
            tx.input[cur].witness.witness_script().map(|s| s.as_bytes()).unwrap_or(&[])
        } else if prevouts[cur].script_pubkey.is_p2tr() {
            tx.input[cur].witness.tapscript().map(|s| s.as_bytes()).unwrap_or(&[])
        } else {
            &[]
        };
        engine.input(&sha256::Hash::hash(&ss)[..]);
    }

    if (global & TXFS_CURRENT_INPUT_CONTROL_BLOCK) != 0 {
        let cb = if prevouts[cur].script_pubkey.is_p2tr() {
            tx.input[cur].witness.taproot_control_block().unwrap_or(&[])
        } else {
            &[]
        };
        engine.input(&sha256::Hash::hash(&cb)[..]);
    }

    if (global & TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS) != 0 {
        let pos = current_input_last_codeseparator_pos.unwrap_or(u32::MAX);
        (pos as u32).consensus_encode(&mut engine).unwrap();
    }

    let inout_fields = match bytes.next() {
        Some(b) => b,
        // Stop early if no inputs or outputs are selected.
        None => return Ok(sha256::Hash::from_engine(engine)),
    };

    // Inputs
    let (input_select, commit_number_inputs) = parse_inout_selection(
        &mut bytes, tx.input.len(), current_input_idx, true,
    )?;

    if commit_number_inputs {
        (tx.input.len() as u32).consensus_encode(&mut engine).unwrap();
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_PREVOUTS) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                tx.input[*i].previous_output.consensus_encode(&mut engine).unwrap();
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_SEQUENCES) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                tx.input[*i].sequence.consensus_encode(&mut engine).unwrap();
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_SCRIPTSIGS) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                engine.input(&sha256::Hash::hash(&tx.input[*i].script_sig.as_bytes())[..]);
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_PREV_SCRIPTPUBKEYS) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                engine.input(&sha256::Hash::hash(&prevouts[*i].script_pubkey.as_bytes())[..]);
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_PREV_VALUES) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                prevouts[*i].value.consensus_encode(&mut engine).unwrap();
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_TAPROOT_ANNEXES) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                if prevouts[*i].script_pubkey.is_p2tr() {
                    if let Some(annex) = tx.input[*i].witness.taproot_annex() {
                        engine.input(&sha256::Hash::hash(annex)[..]);
                    } else {
                        engine.input(&SHA256_EMPTY[..]);
                    }
                } else {
                    engine.input(&SHA256_EMPTY[..]);
                }
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    // Outputs
    if bytes.peek().is_none() {
    } else {
        let allow_empty = (inout_fields & TXFS_OUTPUTS_ALL) == 0;
        let (selection, commit_number) = parse_inout_selection(
            &mut bytes, tx.output.len(), current_input_idx, allow_empty,
        )?;

        if commit_number {
            (tx.output.len() as u32).consensus_encode(&mut engine).unwrap();
        }

        if !selection.is_empty() && (inout_fields & TXFS_OUTPUTS_SCRIPTPUBKEYS) != 0 {
            let hash = {
                let mut engine = sha256::Hash::engine();
                for i in &selection {
                    engine.input(&sha256::Hash::hash(&tx.output[*i].script_pubkey.as_bytes())[..]);
                }
                sha256::Hash::from_engine(engine)
            };
            hash.consensus_encode(&mut engine).unwrap();
        }

        if !selection.is_empty() && (inout_fields & TXFS_OUTPUTS_VALUES) != 0 {
            let hash = {
                let mut engine = sha256::Hash::engine();
                for i in &selection {
                    tx.output[*i].value.consensus_encode(&mut engine).unwrap();
                }
                sha256::Hash::from_engine(engine)
            };
            hash.consensus_encode(&mut engine).unwrap();
        }
    }

    if bytes.next().is_some() {
        return Err("unused txfs bytes");
    }
    Ok(sha256::Hash::from_engine(engine))
}

mod test_vectors {
    use super::*;
    use std::any::Any;
    use std::ops::{self, RangeBounds};
    use bitcoin::hex::DisplayHex;
    use bitcoin::{Amount, ScriptBuf, Sequence, Witness};
    use bitcoin::blockdata::transaction::{self, TxIn};
    use bitcoin::opcodes::all::*;

    fn test_vector_tx() -> (Transaction, Vec<TxOut>) {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(42),
            input: vec![
                TxIn {
                    previous_output: "1111111111111111111111111111111111111111111111111111111111111111:1".parse().unwrap(),
                    script_sig: vec![0x23].into(),
                    sequence: Sequence::from_consensus(1),
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: "2222222222222222222222222222222222222222222222222222222222222222:2".parse().unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(3),
                    witness: { // p2wsh annex-like stack element
                        let mut buf = Witness::new();
                        buf.push(vec![0x13]);
                        buf.push(vec![0x14]);
                        buf.push(vec![0x50, 0x42]); // annex
                        buf
                    },
                },
                TxIn {
                    previous_output: "3333333333333333333333333333333333333333333333333333333333333333:3".parse().unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(2),
                    witness: {
                        let mut buf = Witness::new();
                        buf.push(vec![0x12]);
                        buf
                    },
                },
                TxIn {
                    previous_output: "4444444444444444444444444444444444444444444444444444444444444444:4".parse().unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(3),
                    witness: {
                        let mut buf = Witness::new();
                        buf.push(vec![0x13]);
                        buf.push(vec![0x14]);
                        buf.push(vec![0x50, 0x42]); // annex
                        buf
                    },
                },
            ],
            output: vec![
                TxOut {
                    script_pubkey: vec![OP_PUSHNUM_6.to_u8()].into(),
                    value: Amount::from_sat(350),
                },
                TxOut {
                    script_pubkey: vec![OP_PUSHNUM_7.to_u8()].into(),
                    value: Amount::from_sat(351),
                },
                TxOut {
                    script_pubkey: vec![OP_PUSHNUM_8.to_u8()].into(),
                    value: Amount::from_sat(353),
                },
            ],
        };
        let prevs = vec![
            TxOut {
                script_pubkey: vec![OP_PUSHNUM_16.to_u8()].into(),
                value: Amount::from_sat(360),
            },
            TxOut {
                script_pubkey: vec![ // p2wsh
                    0x00, 0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ].into(),
                value: Amount::from_sat(361),
            },
            TxOut {
                script_pubkey: vec![ // p2tr
                    0x51, 0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ].into(),
                value: Amount::from_sat(361),
            },
            TxOut {
                script_pubkey: vec![ // p2tr
                    0x51, 0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ].into(),
                value: Amount::from_sat(362),
            },
        ];
        (tx, prevs)
    }

    #[derive(Debug)]
    struct TestCase {
        tx: Transaction,
        prevs: Vec<TxOut>,
        vectors: Vec<TestVector>
    }

    #[derive(Debug)]
    struct TestVector {
        txfs: Vec<u8>,
        input: usize,
        codeseparator: Option<u32>,
        txhash: sha256::Hash,
    }

    fn generate_vectors() -> Vec<TestCase> {
        let all = TXFS_ALL;
        let allio = TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL;
        let selnone = TXFS_INOUT_SELECTION_NONE; // 0x00
        let selcur = TXFS_INOUT_SELECTION_CURRENT;
        let selall = TXFS_INOUT_SELECTION_ALL;
        let number = TXFS_INOUT_NUMBER;
        let leading = 0;
        let individual = TXFS_INOUT_SELECTION_MODE;
        let absolute = 0;
        let relative = TXFS_INOUT_INDIVIDUAL_MODE;

        let nbout = 3;

        fn r<T: RangeBounds<usize> + 'static>(t: T) -> Box<dyn Any> {
            Box::new(t)
        }

        // txfs and range of inputs to run it on
        let selectors: &[(&[u8], Box<dyn Any>)] = &[
            // global
            (&[1 << 0], r(..)),
            (&[1 << 1], r(..)),
            (&[1 << 2], r(..)),
            (&[1 << 3], r(..)),
            (&[1 << 4], r(..)),
            (&[0x9f], r(..)),
            // outputs
            (&[all, 0,                          0, number | selnone], r(..)),
            (&[all, TXFS_OUTPUTS_SCRIPTPUBKEYS, 0, selcur], r(..nbout)),
            (&[all, TXFS_OUTPUTS_VALUES,        0, selcur], r(..nbout)),
            (&[all, TXFS_OUTPUTS_ALL,           0, selcur], r(..nbout)),
            (&[all, TXFS_OUTPUTS_SCRIPTPUBKEYS, 0, selall], r(..)),
            (&[all, TXFS_OUTPUTS_VALUES,        0, selall], r(..)),
            (&[all, TXFS_OUTPUTS_ALL,           0, selall], r(..)),
            (&[all, TXFS_OUTPUTS_SCRIPTPUBKEYS, 0, number | selcur], r(..nbout)),
            (&[all, TXFS_OUTPUTS_VALUES,        0, number | selcur], r(..nbout)),
            (&[all, TXFS_OUTPUTS_ALL,           0, number | selcur], r(..nbout)),
            (&[all, TXFS_OUTPUTS_SCRIPTPUBKEYS, 0, number | selall], r(..)),
            (&[all, TXFS_OUTPUTS_VALUES,        0, number | selall], r(..)),
            (&[all, TXFS_OUTPUTS_ALL,           0, number | selall], r(..)),
            // inputs
            (&[all, 0,                              number | selnone], r(..)),
            (&[all, TXFS_INPUTS_PREVOUTS,           selcur], r(..)),
            (&[all, TXFS_INPUTS_SEQUENCES,          selcur], r(..)),
            (&[all, TXFS_INPUTS_SCRIPTSIGS,         selcur], r(..)),
            (&[all, TXFS_INPUTS_PREV_SCRIPTPUBKEYS, selcur], r(..)),
            (&[all, TXFS_INPUTS_PREV_VALUES,        selcur], r(..)),
            (&[all, TXFS_INPUTS_TAPROOT_ANNEXES,    selcur], r(..)),
            (&[all, TXFS_INPUTS_ALL,                selcur], r(..)),
            (&[all, TXFS_INPUTS_PREVOUTS,           selall], r(..)),
            (&[all, TXFS_INPUTS_SEQUENCES,          selall], r(..)),
            (&[all, TXFS_INPUTS_SCRIPTSIGS,         selall], r(..)),
            (&[all, TXFS_INPUTS_PREV_SCRIPTPUBKEYS, selall], r(..)),
            (&[all, TXFS_INPUTS_PREV_VALUES,        selall], r(..)),
            (&[all, TXFS_INPUTS_TAPROOT_ANNEXES,    selall], r(..)),
            (&[all, TXFS_INPUTS_ALL,                selall], r(..)),
            (&[all, TXFS_INPUTS_PREVOUTS,           number | selcur], r(..)),
            (&[all, TXFS_INPUTS_SEQUENCES,          number | selcur], r(..)),
            (&[all, TXFS_INPUTS_SCRIPTSIGS,         number | selcur], r(..)),
            (&[all, TXFS_INPUTS_PREV_SCRIPTPUBKEYS, number | selcur], r(..)),
            (&[all, TXFS_INPUTS_PREV_VALUES,        number | selcur], r(..)),
            (&[all, TXFS_INPUTS_TAPROOT_ANNEXES,    number | selcur], r(..)),
            (&[all, TXFS_INPUTS_ALL,                number | selcur], r(..)),
            (&[all, TXFS_INPUTS_PREVOUTS,           number | selall], r(..)),
            (&[all, TXFS_INPUTS_SEQUENCES,          number | selall], r(..)),
            (&[all, TXFS_INPUTS_SCRIPTSIGS,         number | selall], r(..)),
            (&[all, TXFS_INPUTS_PREV_SCRIPTPUBKEYS, number | selall], r(..)),
            (&[all, TXFS_INPUTS_PREV_VALUES,        number | selall], r(..)),
            (&[all, TXFS_INPUTS_TAPROOT_ANNEXES,    number | selall], r(..)),
            (&[all, TXFS_INPUTS_ALL,                number | selall], r(..)),
            // both
            (&[all, allio, selall, selall], r(..)),
            (&[all, allio, selcur, selcur], r(..nbout)),
            (&[all, 0,     number | selnone, number | selnone], r(..)),
            (&[all, allio, number | selall,  number | selall], r(..)),
            (&[all, allio, number | selcur,  number | selcur], r(..nbout)),
            (&[all, allio, selcur, selall], r(..)),
            (&[all, allio, selall, selcur], r(..nbout)),
            // leading
            (&[all, allio, leading | 0x01,  number | leading | 0x02], r(..)),
            (&[all, allio, number | selcur, leading | 0x02], r(..nbout)),
            // individual absolute
            (&[all, allio,          individual | absolute | 0x01, 0x01,
                                    individual | absolute | 0x02, 0x00, 0x02], r(..)),
            (&[all, allio, number | individual | absolute | 0x01, 0x01,
                           number | individual | absolute | 0x02, 0x00, 0x02], r(..)),
            // individual relative
            (&[all, allio,          individual | relative | 0x01, (-1i8 as u8) >> 1,
                                    individual | relative | 0x02, (-1i8 as u8) >> 1, 0], r(1..nbout)),
            (&[all, allio, number | individual | relative | 0x01, (-1i8 as u8) >> 1,
                           number | individual | relative | 0x02, (-1i8 as u8) >> 1, 0], r(1..nbout)),
            //TODO(stevenroose) test index size, but for that we need > 32 in/outputs
            // special cases
            (&[], r(..)),
            (&[0x00], r(..)),
        ];

        let cases = vec![
            test_vector_tx(),
        ];

        fn check_range(r: &Box<dyn Any>, idx: usize) -> bool {
            if let Some(ref range) = r.downcast_ref::<ops::RangeFull>() {
                return range.contains(&idx);
            }
            if let Some(ref range) = r.downcast_ref::<ops::Range<usize>>() {
                return range.contains(&idx);
            }
            if let Some(ref range) = r.downcast_ref::<ops::RangeFrom<usize>>() {
                return range.contains(&idx);
            }
            if let Some(ref range) = r.downcast_ref::<ops::RangeTo<usize>>() {
                return range.contains(&idx);
            }
            unreachable!("invalid range type used: {:?}", r.type_id());
        }

        cases.into_iter().enumerate().map(|(cidx, (tx, prevs))| {
            let mut vectors = Vec::new();
            for (_sidx, (txfs, idx_range)) in selectors.iter().enumerate() {
                for i in 0..tx.input.len() {
                    // println!("{} >> #{} ({}) >> {}", cidx, _sidx, txfs.as_hex(), i);
                    if !check_range(idx_range, i) {
                        continue;
                    }

                    match calculate_txhash(txfs, &tx, &prevs, i as u32, None) {
                        Ok(txhash) => vectors.push(TestVector {
                            txfs: txfs.to_vec(),
                            input: i,
                            codeseparator: None,
                            txhash: txhash,
                        }),
                        Err(e) => panic!("Error in vector #{} for selector {}: {}",
                            cidx, txfs.as_hex(), e,
                        ),
                    }
                }
            }
            TestCase { tx, prevs, vectors }
        }).collect()
    }

    pub fn write_vector_file(path: impl AsRef<std::path::Path>) {
        use bitcoin::consensus::encode::serialize_hex;

        let ret = generate_vectors().into_iter().enumerate().map(|(i_tx, c)| serde_json::json!({
            "tx": serialize_hex(&c.tx),
            "prevs": c.prevs.iter().map(|p| serialize_hex(p)).collect::<Vec<_>>(),
            "vectors": c.vectors.into_iter().enumerate().map(|(i_v, v)| serde_json::json!({
                "id": format!("{}:{} ({} #{})", i_tx, i_v, v.txfs.as_hex(), v.input),
                "txfs": v.txfs.as_hex().to_string(),
                "input": v.input,
                "codeseparator": v.codeseparator,
                "txhash": v.txhash,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>();

        let mut file = std::fs::File::create(path).unwrap();
        serde_json::to_writer_pretty(&mut file, &ret).unwrap();
    }
}

fn main() {
    test_vectors::write_vector_file("./txhash_vectors.json");
}
