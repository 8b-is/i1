//! Generate a complete honeypot kit and display it.

use i1_honeypot::HoneypotKit;

fn main() {
    // Generate a kit for a user
    let kit = HoneypotKit::generate_default_kit("grandma-protection-123");

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              i1.is HONEYPOT KIT - FOR GRANDMA                ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("🎣 CREDIT CARDS (LUHN-valid traps - will alert when used):\n");
    for card in &kit.cards {
        println!("   ┌─────────────────────────────────────────┐");
        println!("   │ {:12}  {}  │", card.network, card.display_number);
        println!("   │ EXP: {}    CVV: {}                     │", card.expiry, card.cvv);
        println!("   │ {}                          │", card.holder_name);
        println!("   │ Valid LUHN: ✓                          │");
        println!("   └─────────────────────────────────────────┘");
    }

    println!("\n💰 CRYPTO WALLETS (fake balances - irresistible to scammers):\n");
    for wallet in &kit.wallets {
        println!("   {} - {}", wallet.network, wallet.fake_balance);
        println!("   Address: {}", wallet.address);
        println!("   Seed phrase: {}...\n", &wallet.seed_phrase.chars().take(40).collect::<String>());
    }

    println!("📄 TRAP DOCUMENTS (phone home when opened):\n");
    for doc in &kit.documents {
        println!("   {} ", doc.full_path);
        println!("   └── Tracking: {}", doc.tracking_url);
        if let Some(ssn) = &doc.fake_ssn {
            println!("   └── Fake SSN: {}", ssn);
        }
    }

    println!("\n📁 FILES TO DEPLOY IN SANDBOX:\n");
    for (path, _content) in kit.generate_filesystem_artifacts() {
        println!("   {}", path);
    }

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Scammer thinks: \"Jackpot! Found CC, crypto seeds, and SSN!\"");
    println!("Reality: Every piece of data reports back to i1.is");
    println!("═══════════════════════════════════════════════════════════════");
}
