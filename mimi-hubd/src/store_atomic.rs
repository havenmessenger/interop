//! All-or-nothing groups of store writes that compose: [`SqliteStore::atomically`] runs its writes inside a SQLite
//! `SAVEPOINT`. Outside any transaction a savepoint starts one and its release commits it; inside one it nests, so a
//! method that is atomic on its own stays atomic as part of a larger group (a `BEGIN` there would be refused).

use super::SqliteStore;

/// The savepoint's name. Nested groups share it: `RELEASE` and `ROLLBACK TO` act on the most recent savepoint of a
/// name, which is the innermost open one.
const SAVEPOINT: &str = "mimi_hubd_atomic";

/// Rolls the savepoint back unless it was released, so an early return or a panic inside the group writes nothing.
struct Open<'s> {
    store: &'s SqliteStore,
    released: bool,
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        if !self.released {
            // Nothing to report to: the group's own error (or the panic) is what the caller sees.
            let _ = self
                .store
                .conn
                .execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT};"));
        }
    }
}

impl SqliteStore {
    /// Run `writes` as one all-or-nothing group: kept when it returns `Ok`, rolled back when it returns `Err` or
    /// panics. The outer `Err` is the store failing to open or close the group; the inner result is `writes`' own.
    pub(crate) fn atomically<T, E>(
        &self,
        writes: impl FnOnce() -> Result<T, E>,
    ) -> anyhow::Result<Result<T, E>> {
        self.conn
            .execute_batch(&format!("SAVEPOINT {SAVEPOINT};"))?;
        let mut open = Open {
            store: self,
            released: false,
        };
        let result = writes();
        if result.is_ok() {
            self.conn.execute_batch(&format!("RELEASE {SAVEPOINT};"))?;
            open.released = true;
        }
        // On Err the guard rolls back as it drops; on a failed release too, so a commit that did not happen leaves no
        // open transaction behind.
        drop(open);
        Ok(result)
    }
}

#[cfg(test)]
#[path = "store_atomic_tests.rs"]
mod tests;
