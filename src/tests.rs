#[cfg(test)]
mod tests {
    use crate::Finding;
    use validator::{ValidationError, Validate};

    #[test]
    fn it_works() {
        let f = Finding::new();
        let j = serde_json::to_string(&f);
        println!("{}", j.unwrap());
    }

    #[test]
    fn invalid_data()  {
        let f = Finding::new();

    }
}
