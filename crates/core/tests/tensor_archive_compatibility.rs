// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ml")]

use candle_core::{DType, Tensor};
use std::path::Path;

#[test]
fn reads_the_existing_numpy_archive_after_zip_security_update() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/candle-core/tests/test.npz");
    let tensors = Tensor::read_npz(fixture).expect("read the original NumPy fixture");
    assert_eq!(tensors.len(), 2);
    assert_eq!(tensors[0].0, "x");
    assert_eq!(tensors[1].0, "x_plus_one");
    let values = tensors[1]
        .1
        .to_dtype(DType::U8)
        .expect("convert fixture values")
        .to_vec1::<u8>()
        .expect("read fixture values");
    assert_eq!(values, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
}

#[test]
fn opens_the_existing_pytorch_archives_after_zip_security_update() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/candle-core/tests");
    for (name, key) in [
        ("test.pt", "test"),
        ("fortran_tensor_3d.pth", "tensor_fortran"),
    ] {
        let tensors = candle_core::pickle::PthTensors::new(fixtures.join(name), None)
            .expect("open the original PyTorch fixture");
        tensors
            .get(key)
            .expect("read the original tensor")
            .expect("the original tensor is present");
    }
}
