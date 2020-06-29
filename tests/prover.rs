/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

extern crate vade_evan;

use vade_evan::application::prover::Prover;
use std::collections::HashMap;

#[test]
fn encodes_values_correctly() {
  // Test values taken from https://gist.github.com/swcurran/78e5a9e8d11236f003f6a6263c6619a6
  let mut values: HashMap<String, String> = HashMap::new();
  values.insert("string".to_owned(), "101 Wilson Lane".to_owned());
  values.insert("integer".to_owned(), "87121".to_owned());
  values.insert("empty_string".to_owned(), "".to_owned());
  values.insert("null".to_owned(), "null".to_owned());
  values.insert("none".to_owned(), "None".to_owned());
  values.insert("negative".to_owned(), "-2147483648".to_owned());
  values.insert("float".to_owned(), "0.0".to_owned());
  values.insert("true".to_owned(), "true".to_owned());
  values.insert("false".to_owned(), "false".to_owned());

  let encoded = Prover::encode_values(values);
  assert_eq!(
    encoded.get("string").unwrap().encoded,
    "68086943237164982734333428280784300550565381723532936263016368251445461241953".to_owned()
  );
  assert_eq!(
    encoded.get("integer").unwrap().encoded,
    "87121".to_owned()
  );
  assert_eq!(
    encoded.get("empty_string").unwrap().encoded,
    "102987336249554097029535212322581322789799900648198034993379397001115665086549".to_owned()
  );
  assert_eq!(
    encoded.get("null").unwrap().encoded,
    "52530672535577884712458350945238153986666188697374769927409463847120313432331".to_owned()
  );
  assert_eq!(
    encoded.get("none").unwrap().encoded,
    "99769404535520360775991420569103450442789945655240760487761322098828903685777".to_owned()
  );
  assert_eq!(
    encoded.get("negative").unwrap().encoded,
    "-2147483648".to_owned()
  );
  assert_eq!(
    encoded.get("float").unwrap().encoded,
    "62838607218564353630028473473939957328943626306458686867332534889076311281879".to_owned()
  );
  assert_eq!(
    encoded.get("true").unwrap().encoded,
    "82205459161612687361280696578706529610747648852743065596896330207015226302763".to_owned()
  );
  assert_eq!(
    encoded.get("false").unwrap().encoded,
    "114316671150208966788217069870207997298334791577910814811383388719888122312874".to_owned()
  );
}
