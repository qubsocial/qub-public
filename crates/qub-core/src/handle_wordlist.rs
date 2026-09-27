//! Adjective and noun wordlists for auto-allocated handles.
//!
//! Shape: `<adj>_<noun>_<3 digits>` (see the auto-allocation policy).
//! With the current list sizes the combinatorial space is comfortably
//! larger than 10 million; collision probability stays low enough that
//! a single retry resolves almost every clash.
//!
//! # Constraints
//!
//! - Adjectives: 3-7 ASCII lower-case characters (proposal §2.6).
//! - Nouns: 3-6 ASCII lower-case characters.
//! - No brand-adjacent words (see `handle_reserved.rs` for those).
//! - Culturally neutral; reviewed at PR time.
//!
//! # Drift with the Worker mirror
//!
//! The Cloudflare Worker ships a TypeScript copy of these lists because
//! it cannot depend on this Rust crate at runtime. Worker tests
//! snapshot both lists and assert byte-for-byte equality on CI so
//! drift is visible in PR review.

/// Maximum adjective length, per proposal §2.6.
pub const ADJECTIVE_MAX_LEN: usize = 7;

/// Maximum noun length, per proposal §2.6.
pub const NOUN_MAX_LEN: usize = 6;

/// Minimum word length on both lists.
pub const WORD_MIN_LEN: usize = 3;

/// Sorted adjective list (3-7 ASCII lower-case chars). Keep sorted for
/// deterministic diffs in PR review; the allocator indexes randomly so
/// order does not affect the output distribution.
pub const ADJECTIVES: &[&str] = &[
    "agile", "airy", "alert", "amber", "ample", "amused", "ancient", "apt", "ardent", "ashen",
    "autumn", "azure", "baked", "balmy", "bare", "bashful", "beaded", "beige", "benign", "blithe",
    "blue", "blunt", "bold", "boreal", "brave", "brazen", "breezy", "bright", "brisk", "bronze",
    "brown", "bubbly", "buoyant", "burly", "busy", "calm", "candid", "canny", "careful", "casual",
    "cedar", "chalky", "chatty", "cheery", "chilly", "civic", "classic", "clean", "clear",
    "clever", "cloudy", "cobalt", "cogent", "cold", "comic", "cool", "copper", "cordial", "cosmic",
    "cosy", "courtly", "cozy", "crafty", "creamy", "crimson", "crisp", "cunning", "curious",
    "daily", "damp", "dapper", "daring", "dashing", "dawn", "dazed", "dear", "deft", "devout",
    "dewy", "distant", "divine", "docile", "downy", "dusky", "dusty", "eager", "early", "earthy",
    "eased", "easy", "ebony", "elated", "eminent", "endless", "epic", "equine", "even", "exact",
    "fabled", "fair", "famed", "fancy", "faraway", "fickle", "fiery", "fine", "firm", "first",
    "flaxen", "fleet", "fluent", "fluffy", "fond", "formal", "frail", "frank", "free", "fresh",
    "frosted", "frosty", "frozen", "gallant", "gaseous", "genial", "gentle", "giddy", "gilded",
    "glacial", "glassy", "glinty", "glossy", "glowing", "golden", "grand", "granite", "grave",
    "green", "groovy", "gusty", "hale", "handy", "happy", "hardy", "harvest", "hazel", "hazy",
    "heated", "heavy", "hefty", "helpful", "hidden", "high", "hollow", "holy", "homely", "honest",
    "hopeful", "hushed", "icy", "idle", "indigo", "inky", "iron", "ivory", "jade", "jaunty",
    "jovial", "joyful", "joyous", "juicy", "keen", "kind", "kindly", "lacy", "large", "lasting",
    "latent", "lean", "light", "lilac", "linen", "lithe", "lively", "lofty", "lone", "long",
    "lucid", "lucky", "lulled", "lunar", "lush", "magic", "mango", "marbled", "mauve", "meek",
    "mellow", "merry", "mighty", "mild", "minor", "minted", "misty", "mobile", "modest", "mossy",
    "mystic", "napping", "native", "neat", "new", "nimble", "noble", "noisy", "north", "novel",
    "nutmeg", "oaken", "olive", "opal", "open", "orange", "outer", "pale", "partial", "patient",
    "peachy", "perky", "pert", "pewter", "pillowy", "pious", "placid", "plain", "plush", "poetic",
    "polar", "polite", "poplar", "primal", "prism", "proud", "prudent", "puffy", "pungent",
    "puzzled", "quaint", "quick", "quiet", "radiant", "rainy", "rapid", "rare", "raven", "ready",
    "regal", "regular", "relaxed", "restful", "ripe", "rising", "rosy", "round", "royal", "ruby",
    "rustic",
];

/// Sorted noun list (3-6 ASCII lower-case chars). Same ordering
/// convention as [`ADJECTIVES`].
pub const NOUNS: &[&str] = &[
    "acorn", "ally", "anchor", "apple", "arbor", "arc", "archer", "arrow", "artist", "aspen",
    "atlas", "attic", "aurora", "autumn", "axis", "badger", "bard", "bark", "barn", "basin",
    "basket", "beach", "beacon", "beagle", "bean", "bear", "beaver", "bell", "bench", "berry",
    "bison", "blade", "boat", "book", "boot", "borage", "bough", "bower", "brace", "brake",
    "branch", "bread", "breeze", "bridge", "brook", "broom", "buck", "buckle", "burrow", "bush",
    "butler", "cabin", "cactus", "camel", "canary", "candle", "canoe", "canyon", "cape", "carob",
    "castle", "cat", "cedar", "chapel", "cherry", "cider", "clay", "cliff", "cloud", "clover",
    "coast", "cocoa", "comet", "crane", "crest", "crier", "crocus", "crow", "dahlia", "daisy",
    "dawn", "deer", "delta", "dew", "diary", "divot", "docent", "dog", "dome", "drover", "duchy",
    "dune", "dusk", "eagle", "echo", "ember", "envoy", "eon", "fable", "falcon", "fawn", "fen",
    "fennel", "fern", "field", "finch", "fir", "flame", "fleet", "flint", "flora", "flower",
    "flute", "fog", "fold", "forest", "fox", "frost", "fruit", "galaxy", "garden", "garnet",
    "gate", "gem", "geyser", "glade", "glen", "glider", "globe", "glow", "grain", "grape", "grass",
    "grotto", "grove", "guide", "gull", "harbor", "harp", "haven", "hawk", "hazel", "heath",
    "heron", "hill", "hollow", "hoof", "icon", "inlet", "island", "ivy", "jasper", "jay", "kettle",
    "knoll", "lagoon", "lake", "lamb", "lark", "leaf", "ledge", "lichen", "lily", "lion", "loch",
    "locust", "lodge", "lotus", "lynx", "mage", "magpie", "manor", "maple", "marina", "marsh",
    "meadow", "melody", "mentor", "meteor", "mill", "mist", "moat", "monk", "moon", "moor", "moth",
    "motto", "mouse", "muse", "myth", "nectar", "needle", "nest", "oak", "oasis", "ocean",
    "oracle", "orbit", "orca", "orchid", "orion", "otter", "owl", "palm", "panda", "pansy", "path",
    "pebble", "petal", "piano", "pine", "piper", "plank", "plum", "poet", "pond", "poppy", "prism",
    "quartz", "quill", "quince", "rain", "raven", "reed", "reef", "rhea", "ridge", "rill", "river",
    "rivet", "roam", "robin", "rook", "rose", "rover", "runner", "rye", "sable", "sail",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjectives_respect_length_and_charset() {
        for word in ADJECTIVES {
            assert!(
                word.len() >= WORD_MIN_LEN && word.len() <= ADJECTIVE_MAX_LEN,
                "adjective {word:?} outside 3..=7"
            );
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase()),
                "adjective {word:?} contains non-lowercase ASCII"
            );
        }
    }

    #[test]
    fn nouns_respect_length_and_charset() {
        for word in NOUNS {
            assert!(
                word.len() >= WORD_MIN_LEN && word.len() <= NOUN_MAX_LEN,
                "noun {word:?} outside 3..=6"
            );
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase()),
                "noun {word:?} contains non-lowercase ASCII"
            );
        }
    }

    #[test]
    fn adjectives_sorted_and_deduped() {
        for window in ADJECTIVES.windows(2) {
            assert!(
                window[0] < window[1],
                "adjective list order/dup violation at {:?} / {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn nouns_sorted_and_deduped() {
        for window in NOUNS.windows(2) {
            assert!(
                window[0] < window[1],
                "noun list order/dup violation at {:?} / {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn adjectives_have_healthy_cardinality() {
        assert!(
            ADJECTIVES.len() >= 128,
            "adjective list has {} entries; allocator expects >= 128",
            ADJECTIVES.len()
        );
    }

    #[test]
    fn nouns_have_healthy_cardinality() {
        assert!(
            NOUNS.len() >= 128,
            "noun list has {} entries; allocator expects >= 128",
            NOUNS.len()
        );
    }

    #[test]
    fn allocator_combinations_fit_in_handle_bounds() {
        use crate::handle::{HANDLE_MAX_LEN, HANDLE_MIN_LEN};
        // Longest possible allocated handle: max_adj + _ + max_noun + _ + 3 digits
        let longest = ADJECTIVE_MAX_LEN + 1 + NOUN_MAX_LEN + 1 + 3;
        assert!(
            longest <= HANDLE_MAX_LEN,
            "longest allocated handle ({longest}) exceeds HANDLE_MAX_LEN"
        );
        let shortest = WORD_MIN_LEN + 1 + WORD_MIN_LEN + 1 + 3;
        assert!(shortest >= HANDLE_MIN_LEN);
    }

    #[test]
    fn no_reserved_words_in_adjectives() {
        use crate::handle_reserved::is_reserved_lower;
        for word in ADJECTIVES {
            assert!(
                !is_reserved_lower(word),
                "adjective {word:?} collides with reserved list"
            );
        }
    }

    #[test]
    fn no_reserved_words_in_nouns() {
        use crate::handle_reserved::is_reserved_lower;
        for word in NOUNS {
            assert!(
                !is_reserved_lower(word),
                "noun {word:?} collides with reserved list"
            );
        }
    }
}
