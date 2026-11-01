use tokio_postgres::error::{DbError, SqlState};

/// An error from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The connection string or pool settings are not usable.
    #[error("parsing database URL: {0}")]
    Config(String),
    /// The driver or the server reported a failure.
    #[error("{}", display_pg(.0))]
    Pg(#[from] tokio_postgres::Error),
    /// The pool could not hand out a connection.
    #[error("acquiring a connection: {0}")]
    Pool(String),
    /// A query that must return one row returned another count.
    #[error("no rows in result set")]
    NoRows,
}

impl Error {
    /// The server's error, when the server sent one.
    pub fn as_db_error(&self) -> Option<&DbError> {
        match self {
            Error::Pg(err) => err.as_db_error(),
            _ => None,
        }
    }

    /// The server's SQLSTATE, when the server sent one.
    pub fn code(&self) -> Option<&SqlState> {
        self.as_db_error().map(DbError::code)
    }
}

// pgconn.PgError's text: "ERROR: message (SQLSTATE code)".
fn display_pg(err: &tokio_postgres::Error) -> String {
    match err.as_db_error() {
        Some(db) => format!(
            "{}: {} (SQLSTATE {})",
            db.severity(),
            db.message(),
            db.code().code()
        ),
        None => match std::error::Error::source(err) {
            Some(source) => format!("{err}: {source}"),
            None => err.to_string(),
        },
    }
}
