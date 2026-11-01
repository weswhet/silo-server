use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Instant;

use deadpool::managed::Object;
use tokio_postgres::types::Type;
use tokio_postgres::{Row, SimpleQueryMessage, Statement};

use crate::Params;
use crate::error::Error;
use crate::pool::{Conn, Manager};

/// How a statement reaches the server. These are pgx's `QueryExecMode` values the server uses.
///
/// The choice changes plans, not results. Postgres plans a named prepared statement with custom
/// plans for five executions and may then keep a generic one. An unnamed statement is parsed fresh
/// each time and always gets a custom plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecMode {
    /// pgx's default: a named prepared statement, cached on the connection.
    CacheStatement,
    /// Parameter types come from a cached describe, and each execution uses the unnamed statement.
    /// Search and recommendations opt into this for custom plans.
    CacheDescribe,
}

enum Holder {
    Pooled(Box<Object<Manager>>),
    Hijacked(Box<Conn>),
}

/// A pinned connection.
pub struct Session {
    holder: Holder,
}

impl Session {
    pub(crate) fn pooled(object: Object<Manager>) -> Self {
        Self {
            holder: Holder::Pooled(Box::new(object)),
        }
    }

    fn conn(&mut self) -> &mut Conn {
        match &mut self.holder {
            Holder::Pooled(object) => object,
            Holder::Hijacked(conn) => conn,
        }
    }

    /// `pgxpool.Conn.Hijack`: takes the connection out of the pool for good. The pool's slot frees
    /// up, and the connection closes when this session is dropped.
    #[must_use]
    pub fn hijack(self) -> Session {
        let conn = match self.holder {
            Holder::Pooled(object) => Box::new(Object::take(*object)),
            Holder::Hijacked(conn) => conn,
        };
        Session {
            holder: Holder::Hijacked(conn),
        }
    }

    /// Makes the pool discard this connection instead of reusing it, for a session that holds state
    /// a later user must not inherit, such as a session advisory lock.
    pub fn mark_unreusable(&mut self) {
        self.conn().busy = true;
    }

    /// The OID the `vector` type had when this connection was set up.
    pub fn vector_oid(&mut self) -> Option<u32> {
        self.conn().vector_types.vector
    }

    /// The OID the `halfvec` type had when this connection was set up.
    pub fn halfvec_oid(&mut self) -> Option<u32> {
        self.conn().vector_types.halfvec
    }

    /// Runs a query in the pool's default mode.
    pub async fn query(&mut self, sql: &str, params: Params<'_>) -> Result<Vec<Row>, Error> {
        let mode = self.conn().default_mode;
        self.query_mode(mode, sql, params).await
    }

    /// Runs a query in the given mode.
    pub async fn query_mode(
        &mut self,
        mode: ExecMode,
        sql: &str,
        params: Params<'_>,
    ) -> Result<Vec<Row>, Error> {
        let conn = self.conn();
        conn.busy = true;
        let result = run_query(conn, mode, sql, params).await;
        if result.is_err() {
            invalidate(conn, sql);
        }
        conn.busy = false;
        conn.last_used = Instant::now();
        result
    }

    /// `QueryRow`: the first row, or [`Error::NoRows`].
    pub async fn query_one(&mut self, sql: &str, params: Params<'_>) -> Result<Row, Error> {
        self.query(sql, params)
            .await?
            .into_iter()
            .next()
            .ok_or(Error::NoRows)
    }

    /// Runs a statement in the pool's default mode and returns the affected row count.
    ///
    /// With no parameters this uses the simple protocol whatever the mode, as pgx's `Exec` does.
    pub async fn execute(&mut self, sql: &str, params: Params<'_>) -> Result<u64, Error> {
        let mode = self.conn().default_mode;
        self.execute_mode(mode, sql, params).await
    }

    /// Runs a statement in the given mode and returns the affected row count.
    pub async fn execute_mode(
        &mut self,
        mode: ExecMode,
        sql: &str,
        params: Params<'_>,
    ) -> Result<u64, Error> {
        let conn = self.conn();
        conn.busy = true;
        let result = if params.is_empty() {
            run_simple(conn, sql).await
        } else {
            run_execute(conn, mode, sql, params).await
        };
        if result.is_err() {
            invalidate(conn, sql);
        }
        conn.busy = false;
        conn.last_used = Instant::now();
        result
    }

    /// Runs one simple-protocol query string. A string holding several statements runs as one
    /// implicit transaction, so a `CONCURRENTLY` statement has to be sent alone.
    pub async fn batch_execute(&mut self, sql: &str) -> Result<(), Error> {
        let conn = self.conn();
        conn.busy = true;
        let result = conn.client.batch_execute(sql).await.map_err(Error::from);
        conn.busy = false;
        conn.last_used = Instant::now();
        result
    }

    /// Runs one simple-protocol query string and returns its messages, with every value as text.
    pub async fn simple_query(&mut self, sql: &str) -> Result<Vec<SimpleQueryMessage>, Error> {
        let conn = self.conn();
        conn.busy = true;
        let result = conn.client.simple_query(sql).await.map_err(Error::from);
        conn.busy = false;
        conn.last_used = Instant::now();
        result
    }

    /// Opens a transaction. Dropping it without [`Tx::commit`] or [`Tx::rollback`] discards the
    /// connection, and the server rolls back when it closes.
    pub async fn begin(&mut self) -> Result<Tx<'_>, Error> {
        self.batch_execute("BEGIN").await?;
        self.conn().in_tx = true;
        Ok(Tx {
            session: self,
            finished: false,
        })
    }
}

// pgx invalidates a statement and its description when a query using them fails.
fn invalidate(conn: &mut Conn, sql: &str) {
    conn.statements.pop(sql);
    conn.descriptions.pop(sql);
}

async fn cached_statement(conn: &mut Conn, sql: &str) -> Result<Statement, Error> {
    if let Some(statement) = conn.statements.get(sql) {
        return Ok(statement.clone());
    }
    let statement = conn.client.prepare(sql).await?;
    conn.statements.put(sql.to_string(), statement.clone());
    Ok(statement)
}

async fn cached_description(conn: &mut Conn, sql: &str) -> Result<Arc<Vec<Type>>, Error> {
    if let Some(types) = conn.descriptions.get(sql) {
        return Ok(Arc::clone(types));
    }
    // `query_typed` needs parameter OIDs and verbatim SQL carries none, so describe once. The
    // statement closes when it drops here; only its parameter types stay cached.
    let statement = conn.client.prepare(sql).await?;
    let types = Arc::new(statement.params().to_vec());
    conn.descriptions.put(sql.to_string(), Arc::clone(&types));
    Ok(types)
}

fn typed_params<'a>(
    params: Params<'a>,
    types: &[Type],
) -> Result<Vec<(&'a (dyn tokio_postgres::types::ToSql + Sync), Type)>, Error> {
    if params.len() != types.len() {
        return Err(Error::Pool(format!(
            "expected {} arguments, got {}",
            types.len(),
            params.len()
        )));
    }
    Ok(params.iter().copied().zip(types.iter().cloned()).collect())
}

async fn run_query(
    conn: &mut Conn,
    mode: ExecMode,
    sql: &str,
    params: Params<'_>,
) -> Result<Vec<Row>, Error> {
    match mode {
        ExecMode::CacheStatement => {
            let statement = cached_statement(conn, sql).await?;
            Ok(conn.client.query(&statement, params).await?)
        }
        ExecMode::CacheDescribe => {
            let types = cached_description(conn, sql).await?;
            let typed = typed_params(params, &types)?;
            Ok(conn.client.query_typed(sql, &typed).await?)
        }
    }
}

async fn run_execute(
    conn: &mut Conn,
    mode: ExecMode,
    sql: &str,
    params: Params<'_>,
) -> Result<u64, Error> {
    match mode {
        ExecMode::CacheStatement => {
            let statement = cached_statement(conn, sql).await?;
            Ok(conn.client.execute(&statement, params).await?)
        }
        ExecMode::CacheDescribe => {
            let types = cached_description(conn, sql).await?;
            let typed = typed_params(params, &types)?;
            let stream = conn
                .client
                .query_typed_raw(sql, typed.iter().map(|(p, t)| (*p, t.clone())))
                .await?;
            count_rows(stream).await
        }
    }
}

async fn count_rows(stream: tokio_postgres::RowStream) -> Result<u64, Error> {
    use futures_util::StreamExt;
    let mut stream = std::pin::pin!(stream);
    while let Some(row) = stream.next().await {
        row?;
    }
    Ok(stream.rows_affected().unwrap_or(0))
}

// pgx returns the last command's tag for a simple-protocol Exec.
async fn run_simple(conn: &mut Conn, sql: &str) -> Result<u64, Error> {
    let messages = conn.client.simple_query(sql).await?;
    let mut count = 0;
    for message in messages {
        if let SimpleQueryMessage::CommandComplete(n) = message {
            count = n;
        }
    }
    Ok(count)
}

/// An open transaction. It derefs to its [`Session`], so the query methods are available on it.
pub struct Tx<'a> {
    session: &'a mut Session,
    finished: bool,
}

impl Tx<'_> {
    /// Commits.
    pub async fn commit(mut self) -> Result<(), Error> {
        self.finish("COMMIT").await
    }

    /// Rolls back.
    pub async fn rollback(mut self) -> Result<(), Error> {
        self.finish("ROLLBACK").await
    }

    async fn finish(&mut self, sql: &str) -> Result<(), Error> {
        self.session.batch_execute(sql).await?;
        self.session.conn().in_tx = false;
        self.finished = true;
        Ok(())
    }
}

impl Deref for Tx<'_> {
    type Target = Session;

    fn deref(&self) -> &Session {
        self.session
    }
}

impl DerefMut for Tx<'_> {
    fn deref_mut(&mut self) -> &mut Session {
        self.session
    }
}
