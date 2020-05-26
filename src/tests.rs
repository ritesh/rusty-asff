#[cfg(test)]
mod tests {
    use crate::Finding;
    #[test]
    fn it_works() {
        let f = Finding::new();
        let j = serde_json::to_string(&f);
        println!("{}", j.unwrap());
    }

    #[test]
    fn newfinding() {
        let f = Finding::new();
        assert_eq!(f.aws_account_id, "");
    }
}
