#[cfg(test)]
mod tests {
    use crate::Finding;
    use crate::asff::Resource;
    use validator::Validate;
    use std::default::Default;
    use serde_json;

    #[test]
    fn json_serialisation_default_works() {
        //TODO not sure this is needed, if the struct can't be serialized, think compiler would
        //complain?
        let f = Finding::new();
        match serde_json::to_string(&f) {
            Ok(_) => println!("Serialization works on default"),
            Err(_) => panic!("Failed to serialise")
        }
    }

    #[test]
    fn check_validation()  {
        use validator::Validate;
        let f = Finding::new();
        let e = f.validate().unwrap_err();
        //The defaults are garbage, we should get an error on validation
        assert_ne!(true, e.is_empty())
    }
    #[test]
    fn validation_ok()  {
        let mut f = Finding::new();
        f.aws_account_id = "012345678901".to_string();
        f.created_at = "2002-10-02T15:00:00Z".to_string();
        f.generator_id = "test-generator".to_string();
        f.description = "Some rando description".to_string();
        f.id = "test-id".to_string();
        f.resources = vec![Resource{..Default::default()}];
        f.schema_version = "2010-02-02".to_string();
        f.title = "Bigly bad".to_string();
        f.types = vec!["some string".to_string()];
        f.updated_at = "2002-10-02T15:00:00Z".to_string();
        f.validate().unwrap();
    }
    #[test]
    fn validation_and_serialization()  {
        let mut f = Finding::new();
        f.aws_account_id = "012345678901".to_string();
        f.created_at = "2002-10-02T15:00:00Y".to_string();
        f.generator_id = "test-generator".to_string();
        f.description = "Some rando description".to_string();
        f.id = "test-id".to_string();
        f.resources = vec![Resource{..Default::default()}];
        f.schema_version = "2010-02-02".to_string();
        f.title = "Bigly bad".to_string();
        f.types = vec!["some string".to_string()];
        f.updated_at = "2002-10-02T15:00:00Z".to_string();
        match serde_json::to_string(&f) {
            Ok(t)  => println!("{:?}", t),
            Err(e)=> println!("Failed with {:?}", e)
        };
    }
}
