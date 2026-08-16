pub struct Query;

pub fn query(_: &str) -> Query {
    Query
}

impl Query {
    pub async fn execute<T>(self, _: &T) -> Result<(), ()> {
        Ok(())
    }
}

