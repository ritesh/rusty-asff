use asff::Finding;
use serde_yaml;
use validator::Validate;

fn main() {
    let mut f = Finding::new();
    f.aws_account_id = "123".to_string();
    //This will fail since the defaults are rubbish values
    //and we're validating lengths/regexes etc.
    println!("{:?}", f.validate().unwrap());
    println!("{}", serde_yaml::to_string(&f).unwrap());
}
