use crate::swarm::{ChunkProfile, DEFAULT_PIECE_SIZE, MAX_PIECE_SIZE, MIN_PIECE_SIZE};
use sha2::{Digest, Sha256};
use std::io;

pub const MAX_SOURCE_SYMBOLS: usize = 64;
pub const MAX_SYMBOL_BYTES: usize = 1024 * 1024;
pub const MAX_BLOCK_BYTES: usize = MAX_SOURCE_SYMBOLS * MAX_SYMBOL_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairSymbol {
    pub block_id: String,
    pub symbol_index: u32,
    pub coefficients: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TransportMetrics {
    pub throughput_bytes_per_second: f64,
    pub round_trip_ms: f64,
    pub loss_rate: f64,
    pub cpu_budget_fraction: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveDecision {
    pub piece_size: u64,
    pub max_in_flight_pieces: u32,
    pub repair_symbols_per_block: u32,
}

pub fn systematic_symbol(
    block_id: &str,
    symbol_index: usize,
    source_symbols: &[Vec<u8>],
) -> io::Result<RepairSymbol> {
    validate_block(source_symbols)?;
    if symbol_index >= source_symbols.len() {
        return Err(invalid("systematic symbol index out of range"));
    }
    let mut coefficients = vec![0u8; source_symbols.len()];
    coefficients[symbol_index] = 1;
    Ok(RepairSymbol {
        block_id: block_id.to_string(),
        symbol_index: symbol_index as u32,
        coefficients,
        payload: source_symbols[symbol_index].clone(),
    })
}

pub fn generate_repair_symbol(
    block_id: &str,
    repair_index: u32,
    source_symbols: &[Vec<u8>],
) -> io::Result<RepairSymbol> {
    validate_block(source_symbols)?;
    let mut coefficients = Vec::with_capacity(source_symbols.len());
    let mut seed = Sha256::new();
    seed.update(b"zapdrop-fountain-v1");
    seed.update(block_id.as_bytes());
    seed.update(repair_index.to_be_bytes());
    let mut digest = seed.finalize().to_vec();
    while coefficients.len() < source_symbols.len() {
        if digest.is_empty() {
            digest = Sha256::digest(&digest).to_vec();
        }
        let value = digest.remove(0);
        coefficients.push(if value == 0 { 1 } else { value });
    }
    let payload = linear_combine(&coefficients, source_symbols)?;
    Ok(RepairSymbol {
        block_id: block_id.to_string(),
        symbol_index: repair_index,
        coefficients,
        payload,
    })
}

pub fn reconstruct_source_symbols(
    block_id: &str,
    source_count: usize,
    symbol_size: usize,
    symbols: &[RepairSymbol],
) -> io::Result<Vec<Vec<u8>>> {
    if source_count == 0 || source_count > MAX_SOURCE_SYMBOLS || symbol_size == 0 {
        return Err(invalid("invalid fountain block dimensions"));
    }
    if symbol_size > MAX_SYMBOL_BYTES || symbols.len() < source_count {
        return Err(invalid("fountain block exceeds repair limits"));
    }
    let mut rows = symbols
        .iter()
        .filter(|symbol| {
            symbol.block_id == block_id
                && symbol.coefficients.len() == source_count
                && symbol.payload.len() == symbol_size
        })
        .map(|symbol| {
            let mut row = symbol.coefficients.clone();
            row.extend_from_slice(&symbol.payload);
            row
        })
        .collect::<Vec<_>>();
    if rows.len() < source_count {
        return Err(invalid("insufficient compatible repair symbols"));
    }
    let mut pivot = 0usize;
    for column in 0..source_count {
        let Some(row_index) = (pivot..rows.len()).find(|index| rows[*index][column] != 0) else {
            continue;
        };
        rows.swap(pivot, row_index);
        let inverse = gf_inverse(rows[pivot][column]);
        scale_row(&mut rows[pivot], inverse, column, symbol_size);
        let pivot_row = rows[pivot].clone();
        for index in 0..rows.len() {
            if index != pivot && rows[index][column] != 0 {
                let factor = rows[index][column];
                subtract_scaled_row(&mut rows[index], &pivot_row, factor, column, symbol_size);
            }
        }
        pivot += 1;
        if pivot == source_count {
            break;
        }
    }
    if pivot != source_count {
        return Err(invalid("repair symbols are not linearly independent"));
    }
    let mut recovered = vec![vec![0u8; symbol_size]; source_count];
    for row in rows.iter().take(source_count) {
        let Some(index) = row[..source_count].iter().position(|value| *value == 1) else {
            return Err(invalid("repair elimination produced an invalid basis"));
        };
        if row[..source_count]
            .iter()
            .enumerate()
            .any(|(column, value)| column != index && *value != 0)
        {
            return Err(invalid("repair elimination did not reach reduced form"));
        }
        recovered[index].copy_from_slice(&row[source_count..]);
    }
    Ok(recovered)
}

pub fn choose_adaptive_decision(metrics: TransportMetrics) -> AdaptiveDecision {
    let valid_loss = metrics.loss_rate.is_finite() && (0.0..=1.0).contains(&metrics.loss_rate);
    let valid_rtt = metrics.round_trip_ms.is_finite() && metrics.round_trip_ms >= 0.0;
    let valid_cpu = metrics.cpu_budget_fraction.is_finite()
        && (0.0..=1.0).contains(&metrics.cpu_budget_fraction);
    let loss = if valid_loss { metrics.loss_rate } else { 0.0 };
    let rtt = if valid_rtt {
        metrics.round_trip_ms
    } else {
        100.0
    };
    let cpu = if valid_cpu {
        metrics.cpu_budget_fraction
    } else {
        0.5
    };
    let piece_size = if loss > 0.15 || rtt > 250.0 {
        MIN_PIECE_SIZE
    } else if loss > 0.05 || rtt > 80.0 {
        1024 * 1024
    } else {
        DEFAULT_PIECE_SIZE.min(MAX_PIECE_SIZE)
    };
    let max_in_flight_pieces = if cpu < 0.25 || loss > 0.15 {
        2
    } else if rtt > 250.0 {
        4
    } else {
        8
    };
    let repair_symbols_per_block = if loss > 0.15 {
        4
    } else if loss > 0.05 {
        2
    } else {
        0
    };
    AdaptiveDecision {
        piece_size,
        max_in_flight_pieces,
        repair_symbols_per_block,
    }
}

pub fn decision_profile(metrics: TransportMetrics) -> ChunkProfile {
    let decision = choose_adaptive_decision(metrics);
    ChunkProfile {
        profile_id: format!("adaptive-{}", decision.piece_size),
        piece_size: decision.piece_size,
        max_in_flight_pieces: decision.max_in_flight_pieces,
        hash: "sha256".to_string(),
        aead: "x25519-hkdf-sha256-chacha20poly1305".to_string(),
    }
}

fn validate_block(source_symbols: &[Vec<u8>]) -> io::Result<()> {
    if source_symbols.is_empty() || source_symbols.len() > MAX_SOURCE_SYMBOLS {
        return Err(invalid("source symbol count exceeds repair limits"));
    }
    let symbol_size = source_symbols[0].len();
    if symbol_size == 0 || symbol_size > MAX_SYMBOL_BYTES {
        return Err(invalid("source symbol size exceeds repair limits"));
    }
    if source_symbols
        .iter()
        .any(|symbol| symbol.len() != symbol_size)
    {
        return Err(invalid("source symbols have inconsistent sizes"));
    }
    if source_symbols.len().saturating_mul(symbol_size) > MAX_BLOCK_BYTES {
        return Err(invalid("source block exceeds repair limits"));
    }
    Ok(())
}

fn linear_combine(coefficients: &[u8], source_symbols: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    if coefficients.len() != source_symbols.len() {
        return Err(invalid("repair coefficient count mismatch"));
    }
    let mut payload = vec![0u8; source_symbols[0].len()];
    for (coefficient, source) in coefficients.iter().zip(source_symbols) {
        for (output, input) in payload.iter_mut().zip(source) {
            *output ^= gf_mul(*coefficient, *input);
        }
    }
    Ok(payload)
}

fn scale_row(row: &mut [u8], factor: u8, column: usize, symbol_size: usize) {
    let remaining = row.len().saturating_sub(column);
    for value in row.iter_mut().skip(column).take(remaining) {
        *value = gf_mul(*value, factor);
    }
    let _ = symbol_size;
}

fn subtract_scaled_row(
    target: &mut [u8],
    source: &[u8],
    factor: u8,
    column: usize,
    _symbol_size: usize,
) {
    for index in column..target.len() {
        target[index] ^= gf_mul(factor, source[index]);
    }
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high = left & 0x80 != 0;
        left <<= 1;
        if high {
            left ^= 0x1d;
        }
        right >>= 1;
    }
    result
}

fn gf_pow(mut value: u8, mut exponent: u16) -> u8 {
    let mut result = 1u8;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

fn gf_inverse(value: u8) -> u8 {
    debug_assert_ne!(value, 0);
    gf_pow(value, 254)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_missing_systematic_symbols_from_bounded_repair_symbols() {
        let source = vec![
            b"aaaa".to_vec(),
            b"bbbb".to_vec(),
            b"cccc".to_vec(),
            b"dddd".to_vec(),
        ];
        let mut symbols = vec![systematic_symbol("block", 0, &source).unwrap()];
        symbols.push(systematic_symbol("block", 2, &source).unwrap());
        symbols.push(generate_repair_symbol("block", 1, &source).unwrap());
        symbols.push(generate_repair_symbol("block", 2, &source).unwrap());
        let recovered = reconstruct_source_symbols("block", 4, 4, &symbols).unwrap();
        assert_eq!(recovered, source);
    }

    #[test]
    fn adaptive_controller_is_conservative_on_loss_and_high_rtt() {
        let decision = choose_adaptive_decision(TransportMetrics {
            throughput_bytes_per_second: 1_000_000.0,
            round_trip_ms: 300.0,
            loss_rate: 0.2,
            cpu_budget_fraction: 0.5,
        });
        assert_eq!(decision.piece_size, MIN_PIECE_SIZE);
        assert_eq!(decision.max_in_flight_pieces, 2);
        assert_eq!(decision.repair_symbols_per_block, 4);
    }
}
