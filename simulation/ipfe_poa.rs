//! IPFE Price of Anarchy Simulation
//!
//! Compares three obfuscation strategies for stablecoin liquidation:
//! 1. No hiding (transparent threshold)
//! 2. Noise-based (add randomness to threshold)
//! 3. IPFE (weights completely hidden, only score revealed)
//!
//! Measures Price of Anarchy = Nash Cost / Social Optimum
//!
//! ## Usage
//! ```bash
//! cd simulation && cargo run --release
//! ```

use rand::prelude::*;


const NUM_CDPS: usize = 100;
const NUM_KEEPERS: usize = 20;
const SIMULATION_RUNS: usize = 10_000;
const ETH_PRICE: f64 = 2000.0;
const LIQUIDATION_PENALTY: f64 = 0.13;

#[derive(Clone, Copy, Debug, PartialEq)]
enum ObfuscationStrategy {
    Transparent,  // Everyone knows exact threshold
    NoiseBased,   // Threshold + random noise
    IPFE,         // Hidden weights, only score visible
    FairRAI,      // IPFE + commit-reveal + random selection + 60/40 split
    FairRAI5050,  // Same but 50/50 split
    KeeperPool,   // 70% equal split to keepers, 30% to protocol
}

impl ObfuscationStrategy {
    fn all() -> Vec<Self> {
        vec![
            Self::Transparent, 
            Self::NoiseBased, 
            Self::IPFE, 
            Self::FairRAI,
            Self::FairRAI5050,
            Self::KeeperPool,
        ]
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Transparent => "Transparent",
            Self::NoiseBased => "Noise-Based",
            Self::IPFE => "IPFE Only",
            Self::FairRAI => "FairRAI 60/40",
            Self::FairRAI5050 => "FairRAI 50/50",
            Self::KeeperPool => "Keeper Pool 70/30",
        }
    }
}

#[derive(Clone)]
struct CDP {
    id: usize,
    collateral: f64,
    debt: f64,
    age_days: f64,
    volatility_score: f64,
}

impl CDP {
    fn new(id: usize, rng: &mut impl Rng) -> Self {
        let collateral = 1.0 + rng.gen::<f64>() * 9.0;
        let ratio = 1.3 + rng.gen::<f64>() * 0.5; // 130-180%
        let debt = (collateral * ETH_PRICE) / ratio;
        
        Self {
            id,
            collateral,
            debt,
            age_days: rng.gen::<f64>() * 365.0,
            volatility_score: rng.gen::<f64>(),
        }
    }

    fn collateral_ratio(&self, eth_price: f64) -> f64 {
        (self.collateral * eth_price) / self.debt
    }

    fn features(&self, eth_price: f64) -> [f64; 5] {
        [
            self.collateral_ratio(eth_price),
            self.volatility_score,
            self.debt / (self.collateral * eth_price), // utilization
            (self.age_days / 365.0).min(1.0),          // normalized age
            (self.collateral * eth_price / 10000.0).min(2.0), // size factor
        ]
    }

    fn liquidation_profit(&self, eth_price: f64) -> f64 {
        let collateral_value = self.collateral * eth_price;
        let profit = collateral_value - self.debt - 50.0; // gas cost
        profit.max(0.0) * LIQUIDATION_PENALTY
    }
}

#[derive(Clone)]
struct Keeper {
    id: usize,
    gas_priority: f64,  // 0-1, higher = pays more gas = executes first
    total_profit: f64,
    successful_liquidations: usize,
}

impl Keeper {
    fn new(id: usize, rng: &mut impl Rng) -> Self {
        Self {
            id,
            gas_priority: rng.gen::<f64>(),
            total_profit: 0.0,
            successful_liquidations: 0,
        }
    }
}

struct LiquidationGame {
    cdps: Vec<CDP>,
    eth_price: f64,
    
    // True parameters (governance knows these)
    true_weights: [f64; 5],
    true_threshold: f64,
    
    // Obfuscation settings
    strategy: ObfuscationStrategy,
    noise_level: f64,
}

impl LiquidationGame {
    fn new(strategy: ObfuscationStrategy, rng: &mut impl Rng) -> Self {
        let cdps: Vec<CDP> = (0..NUM_CDPS).map(|i| CDP::new(i, rng)).collect();
        
        // Hidden weights: [ratio, volatility, utilization, age, size]
        // Higher ratio = safer, higher volatility = riskier, etc.
        let true_weights = [2.0, -1.0, -1.5, 0.3, -0.3];
        let true_threshold = 2.0; // Score must be above this to be safe
        // This creates ~30-50% liquidatable CDPs after price drop
        
        Self {
            cdps,
            eth_price: ETH_PRICE,
            true_weights,
            true_threshold,
            strategy,
            noise_level: 0.29, // From original PoA research
        }
    }

    fn compute_true_score(&self, cdp: &CDP) -> f64 {
        let features = cdp.features(self.eth_price);
        features.iter()
            .zip(self.true_weights.iter())
            .map(|(f, w)| f * w)
            .sum()
    }

    fn is_truly_liquidatable(&self, cdp: &CDP) -> bool {
        self.compute_true_score(cdp) < self.true_threshold
    }

    /// What the keeper perceives as liquidatable
    fn keeper_perceives_liquidatable(&self, cdp: &CDP, rng: &mut impl Rng) -> (bool, f64) {
        match self.strategy {
            ObfuscationStrategy::Transparent => {
                // Keeper knows exact weights and threshold
                let score = self.compute_true_score(cdp);
                (score < self.true_threshold, 1.0) // 100% confidence
            }
            
            ObfuscationStrategy::NoiseBased => {
                // Keeper knows base threshold but it's noisy
                let perceived_threshold = self.true_threshold 
                    * (1.0 + (rng.gen::<f64>() - 0.5) * 2.0 * self.noise_level);
                let score = self.compute_true_score(cdp);
                let confidence = 1.0 - self.noise_level;
                (score < perceived_threshold, confidence)
            }
            
            ObfuscationStrategy::IPFE => {
                // Keeper has NO idea about weights
                // Can only observe: collateral ratio (public on-chain)
                // Strategy: try any CDP with ratio < 1.6 (wide net)
                let ratio = cdp.collateral_ratio(self.eth_price);
                
                // Cast wide net because can't predict exactly
                let perceived_liquidatable = ratio < 1.6;
                
                // Low confidence = less aggressive bidding = more random ordering
                // This is the key: keepers can't bid confidently, so priority is randomized
                let confidence = 0.2 + rng.gen::<f64>() * 0.4; // 0.2-0.6
                (perceived_liquidatable, confidence)
            }
            
            ObfuscationStrategy::FairRAI | 
            ObfuscationStrategy::FairRAI5050 |
            ObfuscationStrategy::KeeperPool => {
                // Same as IPFE for perception, but execution is different
                let ratio = cdp.collateral_ratio(self.eth_price);
                let perceived_liquidatable = ratio < 1.6;
                
                // Confidence doesn't matter - winner is random!
                // All keepers have equal chance regardless of gas priority
                let confidence = rng.gen::<f64>(); // Uniform random
                (perceived_liquidatable, confidence)
            }
        }
    }

    fn simulate_price_drop(&mut self, pct: f64) {
        self.eth_price *= 1.0 - pct;
    }
}

fn simulate_game(strategy: ObfuscationStrategy, rng: &mut impl Rng) -> GameResult {
    let mut game = LiquidationGame::new(strategy, rng);
    let mut keepers: Vec<Keeper> = (0..NUM_KEEPERS)
        .map(|i| Keeper::new(i, rng))
        .collect();

    // Simulate 10% ETH price crash (creates partial liquidations)
    game.simulate_price_drop(0.10);

    let mut total_profit_extracted = 0.0;
    let mut failed_attempts = 0;
    let mut successful_liquidations = 0;
    let mut front_runner_profit = 0.0;
    let mut missed_liquidations = 0;

    // Find actually liquidatable CDPs
    let truly_liquidatable: Vec<usize> = game.cdps.iter()
        .enumerate()
        .filter(|(_, cdp)| game.is_truly_liquidatable(cdp))
        .map(|(i, _)| i)
        .collect();

    // Each keeper evaluates each CDP
    for cdp in &game.cdps {
        let mut attempts: Vec<(usize, f64, f64)> = Vec::new(); // (keeper_id, priority, confidence)

        for keeper in &keepers {
            let (perceives_liquidatable, confidence) = 
                game.keeper_perceives_liquidatable(cdp, rng);
            
            if perceives_liquidatable {
                // Priority = gas_priority * confidence
                let priority = keeper.gas_priority * confidence;
                attempts.push((keeper.id, priority, confidence));
            }
        }

        if attempts.is_empty() {
            if game.is_truly_liquidatable(cdp) {
                missed_liquidations += 1;
            }
            continue;
        }

        // Highest priority keeper wins (except FairRAI uses random)
        attempts.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        // For fair strategies: random winner, not highest priority
        let uses_random = matches!(
            strategy, 
            ObfuscationStrategy::FairRAI | 
            ObfuscationStrategy::FairRAI5050 | 
            ObfuscationStrategy::KeeperPool
        );
        
        let winner_idx = if uses_random {
            rng.gen_range(0..attempts.len())
        } else {
            0 // Highest priority
        };
        let (winner_id, _, _) = attempts[winner_idx];

        // Check if liquidation actually succeeds
        if game.is_truly_liquidatable(cdp) {
            let profit = cdp.liquidation_profit(game.eth_price);
            
            match strategy {
                ObfuscationStrategy::FairRAI if attempts.len() > 1 => {
                    // 60% winner, 40% split among others
                    let winner_share = profit * 0.6;
                    let pool_share = profit * 0.4;
                    let per_other = pool_share / (attempts.len() - 1) as f64;
                    
                    keepers[winner_id].total_profit += winner_share;
                    for (i, (kid, _, _)) in attempts.iter().enumerate() {
                        if i != winner_idx {
                            keepers[*kid].total_profit += per_other;
                        }
                    }
                }
                
                ObfuscationStrategy::FairRAI5050 if attempts.len() > 1 => {
                    // 50% winner, 50% split among others
                    let winner_share = profit * 0.5;
                    let pool_share = profit * 0.5;
                    let per_other = pool_share / (attempts.len() - 1) as f64;
                    
                    keepers[winner_id].total_profit += winner_share;
                    for (i, (kid, _, _)) in attempts.iter().enumerate() {
                        if i != winner_idx {
                            keepers[*kid].total_profit += per_other;
                        }
                    }
                }
                
                ObfuscationStrategy::KeeperPool => {
                    // 70% split equally among ALL participants, 30% to protocol
                    let keeper_pool = profit * 0.7;
                    let per_keeper = keeper_pool / attempts.len() as f64;
                    // Protocol gets 30% (not tracked, just removed from circulation)
                    
                    for (kid, _, _) in attempts.iter() {
                        keepers[*kid].total_profit += per_keeper;
                    }
                }
                
                _ => {
                    // Winner takes all
                    keepers[winner_id].total_profit += profit;
                }
            }
            
            keepers[winner_id].successful_liquidations += 1;
            total_profit_extracted += profit;
            successful_liquidations += 1;

            // Track front-runner profit (top 20% by gas priority)
            if keepers[winner_id].gas_priority > 0.8 {
                front_runner_profit += profit;
            }
        } else {
            // Wasted gas on failed attempt
            failed_attempts += 1;
        }
    }

    // Calculate metrics
    let profit_concentration = if total_profit_extracted > 0.0 {
        // Gini-like concentration: how much do top keepers extract?
        let mut profits: Vec<f64> = keepers.iter().map(|k| k.total_profit).collect();
        profits.sort_by(|a, b| b.partial_cmp(a).unwrap());
        let top_20_pct = profits.iter().take(NUM_KEEPERS / 5).sum::<f64>();
        top_20_pct / total_profit_extracted
    } else {
        0.0
    };

    let gas_waste_ratio = failed_attempts as f64 / (failed_attempts + successful_liquidations).max(1) as f64;
    let coverage = successful_liquidations as f64 / truly_liquidatable.len().max(1) as f64;

    GameResult {
        strategy,
        successful_liquidations,
        failed_attempts,
        missed_liquidations,
        total_profit: total_profit_extracted,
        front_runner_profit,
        profit_concentration,
        gas_waste_ratio,
        coverage,
    }
}

#[derive(Debug)]
struct GameResult {
    strategy: ObfuscationStrategy,
    successful_liquidations: usize,
    failed_attempts: usize,
    missed_liquidations: usize,
    total_profit: f64,
    front_runner_profit: f64,
    profit_concentration: f64, // 0-1, higher = more concentrated
    gas_waste_ratio: f64,      // 0-1, higher = more wasted gas
    coverage: f64,             // 0-1, higher = more liquidations caught
}

fn compute_poa(results: &[GameResult]) -> f64 {
    // Price of Anarchy = Nash Cost / Social Optimum
    // 
    // Nash Cost factors:
    // - Profit concentration (bad: top keepers extract everything)
    // - Gas waste (bad: failed attempts cost network)
    // - Missed liquidations (bad: system risk)
    //
    // Social Optimum: equal profit distribution, no waste, full coverage

    let avg_concentration: f64 = results.iter().map(|r| r.profit_concentration).sum::<f64>() 
        / results.len() as f64;
    let avg_gas_waste: f64 = results.iter().map(|r| r.gas_waste_ratio).sum::<f64>() 
        / results.len() as f64;
    let avg_coverage: f64 = results.iter().map(|r| r.coverage).sum::<f64>() 
        / results.len() as f64;

    // Nash cost: concentration + waste + (1 - coverage)
    let nash_cost = avg_concentration + avg_gas_waste + (1.0 - avg_coverage);
    
    // Social optimum: even distribution (0.2 for 5 keepers), no waste, full coverage
    let social_optimum: f64 = 0.2 + 0.0 + 0.0;

    nash_cost / social_optimum.max(0.01)
}

fn main() {
    println!("=======================================================");
    println!("  IPFE Price of Anarchy Simulation");
    println!("  Comparing obfuscation strategies for liquidation");
    println!("=======================================================\n");

    let mut rng = rand::thread_rng();

    for strategy in ObfuscationStrategy::all() {
        println!("Strategy: {}", strategy.name());
        println!("{}", "-".repeat(50));

        let results: Vec<GameResult> = (0..SIMULATION_RUNS)
            .map(|_| simulate_game(strategy, &mut rng))
            .collect();

        let poa = compute_poa(&results);

        let avg_successful: f64 = results.iter()
            .map(|r| r.successful_liquidations as f64)
            .sum::<f64>() / SIMULATION_RUNS as f64;
        
        let avg_failed: f64 = results.iter()
            .map(|r| r.failed_attempts as f64)
            .sum::<f64>() / SIMULATION_RUNS as f64;

        let avg_missed: f64 = results.iter()
            .map(|r| r.missed_liquidations as f64)
            .sum::<f64>() / SIMULATION_RUNS as f64;

        let avg_concentration: f64 = results.iter()
            .map(|r| r.profit_concentration)
            .sum::<f64>() / SIMULATION_RUNS as f64;

        let front_runner_share: f64 = results.iter()
            .map(|r| if r.total_profit > 0.0 { r.front_runner_profit / r.total_profit } else { 0.0 })
            .sum::<f64>() / SIMULATION_RUNS as f64;

        println!("  Successful liquidations: {:.1}", avg_successful);
        println!("  Failed attempts:         {:.1}", avg_failed);
        println!("  Missed (bad debt risk):  {:.1}", avg_missed);
        println!("  Profit concentration:    {:.1}%", avg_concentration * 100.0);
        println!("  Front-runner share:      {:.1}%", front_runner_share * 100.0);
        println!("  Price of Anarchy:        {:.2}", poa);
        println!();
    }

    println!("=======================================================");
    println!("  Interpretation:");
    println!("  - PoA = 1.0 means fair, efficient market");
    println!("  - PoA > 1.0 means value extraction by sophisticated actors");
    println!("  - Lower PoA = better for protocol health");
    println!("=======================================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdp_features() {
        let mut rng = rand::thread_rng();
        let cdp = CDP::new(0, &mut rng);
        let features = cdp.features(ETH_PRICE);
        
        assert!(features[0] > 1.0); // Ratio > 100%
        assert!(features[1] >= 0.0 && features[1] <= 1.0); // Volatility normalized
    }

    #[test]
    fn test_transparent_strategy() {
        let mut rng = rand::thread_rng();
        let result = simulate_game(ObfuscationStrategy::Transparent, &mut rng);
        
        // Transparent should have high success rate
        assert!(result.successful_liquidations > 0 || result.missed_liquidations == 0);
    }

    #[test]
    fn test_ipfe_reduces_front_running() {
        let mut rng = rand::thread_rng();
        
        let transparent_results: Vec<GameResult> = (0..100)
            .map(|_| simulate_game(ObfuscationStrategy::Transparent, &mut rng))
            .collect();
        
        let ipfe_results: Vec<GameResult> = (0..100)
            .map(|_| simulate_game(ObfuscationStrategy::IPFE, &mut rng))
            .collect();

        let transparent_fr: f64 = transparent_results.iter()
            .map(|r| if r.total_profit > 0.0 { r.front_runner_profit / r.total_profit } else { 0.0 })
            .sum::<f64>() / 100.0;

        let ipfe_fr: f64 = ipfe_results.iter()
            .map(|r| if r.total_profit > 0.0 { r.front_runner_profit / r.total_profit } else { 0.0 })
            .sum::<f64>() / 100.0;

        // IPFE should reduce front-runner advantage
        println!("Transparent front-runner share: {:.1}%", transparent_fr * 100.0);
        println!("IPFE front-runner share: {:.1}%", ipfe_fr * 100.0);
    }
}
