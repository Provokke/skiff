//! The QPACK static table (RFC 9204 Appendix A) and dynamic table
//! (RFC 9204 3.2), addressed by absolute index.

use super::ENTRY_OVERHEAD;
use std::collections::VecDeque;

pub use super::static_table::STATIC_TABLE;

/// A static table entry by index.
pub fn static_entry(index: u64) -> Option<(&'static [u8], &'static [u8])> {
    STATIC_TABLE.get(usize::try_from(index).ok()?).copied()
}

/// Result of searching a table for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// Name and value match the entry at this index.
    Full(u64),
    /// Only the name matches the entry at this index.
    Name(u64),
}

/// Searches the static table: a full match wins over a name match.
pub fn static_find(name: &[u8], value: &[u8]) -> Option<Match> {
    let mut by_name = None;
    for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
        if *n == name {
            if *v == value {
                return Some(Match::Full(i as u64));
            }
            by_name.get_or_insert(Match::Name(i as u64));
        }
    }
    by_name
}

/// One dynamic table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Field name.
    pub name: Vec<u8>,
    /// Field value.
    pub value: Vec<u8>,
}

impl Entry {
    /// Size for capacity accounting: name + value + 32.
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// The dynamic table: entries in insertion order; the oldest has absolute
/// index `insert_count - len`.
#[derive(Debug, Clone, Default)]
pub struct DynamicTable {
    entries: VecDeque<Entry>,
    size: usize,
    capacity: usize,
    inserted: u64,
}

impl DynamicTable {
    /// An empty table with capacity 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of insertions so far (the Insert Count).
    pub fn insert_count(&self) -> u64 {
        self.inserted
    }

    /// Absolute index of the oldest entry still present.
    pub fn first_index(&self) -> u64 {
        self.inserted - self.entries.len() as u64
    }

    /// Current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current size (sum of entry sizes).
    pub fn size(&self) -> usize {
        self.size
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at absolute index `abs`, unless evicted or not yet inserted.
    pub fn get(&self, abs: u64) -> Option<&Entry> {
        let i = abs.checked_sub(self.first_index())?;
        self.entries.get(usize::try_from(i).ok()?)
    }

    /// How many of the oldest entries must be evicted so that `size` more
    /// bytes fit; `None` if `size` exceeds the capacity.
    pub fn evictions_for(&self, size: usize) -> Option<usize> {
        if size > self.capacity {
            return None;
        }
        let mut free = self.capacity - self.size;
        let mut n = 0;
        while free < size {
            free += self.entries.get(n)?.size();
            n += 1;
        }
        Some(n)
    }

    fn evict(&mut self, n: usize) {
        for _ in 0..n {
            if let Some(e) = self.entries.pop_front() {
                self.size -= e.size();
            }
        }
    }

    /// Sets the capacity, evicting the oldest entries to fit.
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        while self.size > self.capacity {
            self.evict(1);
        }
    }

    /// Inserts an entry, evicting the oldest as needed. Returns false
    /// (changing nothing) if the entry is larger than the capacity.
    #[must_use]
    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) -> bool {
        let e = Entry { name, value };
        let Some(n) = self.evictions_for(e.size()) else {
            return false;
        };
        self.evict(n);
        self.size += e.size();
        self.entries.push_back(e);
        self.inserted += 1;
        true
    }

    /// Searches entries with absolute index below `limit` (newest first):
    /// a full match wins over a name match.
    pub fn find(&self, name: &[u8], value: &[u8], limit: u64) -> Option<Match> {
        let mut by_name = None;
        let first = self.first_index();
        for (i, e) in self.entries.iter().enumerate().rev() {
            let abs = first + i as u64;
            if abs >= limit {
                continue;
            }
            if e.name == name {
                if e.value == value {
                    return Some(Match::Full(abs));
                }
                by_name.get_or_insert(Match::Name(abs));
            }
        }
        by_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_spot_checks() {
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(static_entry(0), Some((&b":authority"[..], &b""[..])));
        assert_eq!(static_entry(17), Some((&b":method"[..], &b"GET"[..])));
        assert_eq!(static_entry(25), Some((&b":status"[..], &b"200"[..])));
        assert_eq!(
            static_entry(52),
            Some((&b"content-type"[..], &b"text/html; charset=utf-8"[..]))
        );
        assert_eq!(
            static_entry(98),
            Some((&b"x-frame-options"[..], &b"sameorigin"[..]))
        );
        assert_eq!(static_entry(99), None);
        assert_eq!(static_find(b":method", b"GET"), Some(Match::Full(17)));
        assert_eq!(static_find(b":method", b"PATCH"), Some(Match::Name(15)));
        assert_eq!(static_find(b"x-custom", b""), None);
        // Every name is lowercase and every entry is unique.
        for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
            assert!(!n.iter().any(u8::is_ascii_uppercase), "{i}");
            assert_eq!(static_find(n, v), Some(Match::Full(i as u64)));
        }
    }

    #[test]
    fn insert_evict_and_index() {
        let mut t = DynamicTable::new();
        assert!(!t.insert(b"a".to_vec(), b"b".to_vec()));
        t.set_capacity(100);
        assert!(t.insert(b"a".to_vec(), b"1".to_vec())); // 34
        assert!(t.insert(b"b".to_vec(), b"2".to_vec())); // 68
        assert_eq!(t.evictions_for(33), Some(1));
        assert_eq!(t.evictions_for(32), Some(0));
        assert_eq!(t.evictions_for(101), None);
        assert!(t.insert(b"c".to_vec(), b"3".to_vec())); // evicts a
        assert_eq!((t.insert_count(), t.first_index(), t.size()), (3, 1, 68));
        assert_eq!(t.get(0), None);
        assert_eq!(t.get(2).unwrap().name, b"c");
        assert_eq!(t.get(3), None);
        assert_eq!(t.find(b"b", b"2", 3), Some(Match::Full(1)));
        assert_eq!(t.find(b"c", b"x", 3), Some(Match::Name(2)));
        assert_eq!(t.find(b"c", b"3", 2), None);
        t.set_capacity(40);
        assert_eq!((t.len(), t.size()), (1, 34));
    }
}
